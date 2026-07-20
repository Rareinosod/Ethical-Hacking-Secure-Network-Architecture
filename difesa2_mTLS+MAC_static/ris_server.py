"""
ris_server.py
==============
Simula il sistema RIS (Radiology Information System).

Versione finale (loop continuo + dati variabili + logging su file + retry):
1. Genera un nuovo messaggio ORU^R01 (referto, Fase 7) ad ogni ciclo, con
   paziente/esame/diagnosi scelti casualmente da un piccolo catalogo.
2. Lo incapsula in MLLP e lo invia SIA al PACS SIA all'HIS (Fase 7).
   In caso di fallimento, ritenta automaticamente fino a MAX_TENTATIVI volte
   prima di registrare l'errore come definitivo.
3. Resta in ascolto su una porta dedicata per ricevere l'ORM^O01 RP (Fase 8).
4. Scrive ogni evento su ris_log.txt (oltre che a schermo): utile per
   allegare le evidenze "prima/dopo attacco" alla presentazione.

Esecuzione in Mininet (dalla CLI di Mininet, dopo run.py):
    his_srv  python3 /home/kali/Desktop/GruppoD/his_server.py &
    h_pacs   python3 /home/kali/Desktop/GruppoD/pacs_server.py &
    h_ris    python3 /home/kali/Desktop/GruppoD/ris_server.py --intervallo 5

Esecuzione locale (test senza Mininet, impostare IP = 127.0.0.1):
    python3 ris_server.py --intervallo 5
    python3 ris_server.py --once       (un solo invio, utile per debug rapido)
"""

#!/usr/bin/env python3
"""
ris_server_tls.py
==============
Simula il sistema RIS (Radiology Information System) con implementazione mTLS.

Versione 2 (Difesa Applicativa):
- Il traffico HL7 viene incapsulato in MLLP e cifrato via TLS.
- Autenticazione reciproca (Mutual TLS): il RIS richiede il certificato
  del PACS/HIS e presenta il proprio certificato per essere autorizzato.
"""

import argparse
import logging
import random
import socket
import threading
import time
import ssl # LIBRERIA AGGIUNTA PER mTLS
import os

from hl7_parser import (
    DEFAULT_HL7_PORT,
    build_oru_r01,
    get_field,
    get_obx_by_codice,
    parse_message,
    pretty_print,
    unwrap_mllp,
    wrap_mllp,
)

# ---------------------------------------------------------------------------
# Configurazione di rete
# ---------------------------------------------------------------------------
PACS_HOST = "10.0.30.20"      
PACS_PORT = DEFAULT_HL7_PORT  

HIS_HOST = "10.0.20.10"       
HIS_PORT = 2577               

RIS_LISTEN_HOST = "0.0.0.0"
RIS_LISTEN_PORT = 2576        

INTERVALLO_DEFAULT_SECONDI = 10
MAX_TENTATIVI = 3    
PAUSA_RETRY_S = 2    

# ---------------------------------------------------------------------------
# Configurazione Certificati mTLS (NOVITÀ)
# Assicurati di generare questi file nella cartella del progetto.
# ---------------------------------------------------------------------------
CERT_DIR = "certs"
RIS_CERT = os.path.join(CERT_DIR, "ris.crt")
RIS_KEY  = os.path.join(CERT_DIR, "ris.key")
CA_CERT  = os.path.join(CERT_DIR, "ca.crt")

# ---------------------------------------------------------------------------
# Setup logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("RIS")
logger.setLevel(logging.DEBUG)
_fmt = logging.Formatter(fmt="%(asctime)s [RIS] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

_ch = logging.StreamHandler()
_ch.setFormatter(_fmt)
logger.addHandler(_ch)

_fh = logging.FileHandler("ris_log.txt", encoding="utf-8")
_fh.setFormatter(_fmt)
logger.addHandler(_fh)

# ---------------------------------------------------------------------------
# Catalogo dati
# ---------------------------------------------------------------------------
PAZIENTI = [
    ("Rossi",    "Mario",    "19800315", "M"),
    ("Bianchi",  "Lucia",    "19750622", "F"),
    ("Verdi",    "Giuseppe", "19920110", "M"),
    ("Colombo",  "Anna",     "19650904", "F"),
    ("Ferrari",  "Luca",     "19881230", "M"),
]

ESAMI_E_REFERTI = [
    {
        "esame":      "TAC^TC Torace",
        "findings":   "Polmoni con addensamento in base destra. Suggestivo per polmonite.",
        "conclusion": "Referto: polmonite lobare destra. Raccomandato follow-up a 30 giorni.",
    },
    {
        "esame":      "RX^Radiografia Torace",
        "findings":   "Campi polmonari liberi da addensamenti. Cuore nei limiti.",
        "conclusion": "Referto: quadro radiografico nella norma.",
    },
    {
        "esame":      "RM^Risonanza Magnetica Encefalo",
        "findings":   "Non si rilevano lesioni focali significative a carico del parenchima.",
        "conclusion": "Referto: esame nella norma, nessuna lesione di rilievo.",
    },
    {
        "esame":      "TAC^TC Addome",
        "findings":   "Fegato di dimensioni regolari, lieve steatosi diffusa.",
        "conclusion": "Referto: steatosi epatica lieve. Si consiglia controllo ecografico a 6 mesi.",
    },
]

RADIOLOGI = ["RAD001", "RAD002", "RAD003"]


def genera_referto_casuale() -> tuple[str, str]:
    cognome, nome, data_nascita, sesso = random.choice(PAZIENTI)
    esame_info = random.choice(ESAMI_E_REFERTI)
    radiologo  = random.choice(RADIOLOGI)

    numero_caso      = random.randint(1000, 9999)
    paziente_id      = f"PAZ{numero_caso}"
    ordine_id        = f"ORD{numero_caso}"
    accession_number = f"ACC{numero_caso}"

    testo_hl7 = build_oru_r01(
        paziente_id=paziente_id,
        cognome=cognome,
        nome=nome,
        data_nascita=data_nascita,
        sesso=sesso,
        ordine_id=ordine_id,
        accession_number=accession_number,
        esame=esame_info["esame"],
        data_esame=time.strftime("%Y%m%d%H%M%S"),
        findings=esame_info["findings"],
        conclusion=esame_info["conclusion"],
        radiologo_id=radiologo,
        msg_id=f"MSG{numero_caso}",
    )
    return testo_hl7, accession_number

# ---------------------------------------------------------------------------
# Invio con retry (MODIFICATO PER mTLS)
# ---------------------------------------------------------------------------
def invia_con_retry(framed: bytes, host: str, porta: int, nome_dest: str) -> bool:
    # 1. Creazione del contesto SSL per il Client
    # Richiediamo l'autenticazione del server e forniamo il nostro certificato
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.load_cert_chain(certfile=RIS_CERT, keyfile=RIS_KEY)
    
    # OPZIONALE: Disabilita il controllo stretto dell'hostname se usi IP crudi in Mininet
    # In produzione non andrebbe rimosso, ma per i lab è spesso necessario
    context.check_hostname = False 

    for tentativo in range(1, MAX_TENTATIVI + 1):
        try:
            with socket.create_connection((host, porta), timeout=5) as sock:
                # 2. Avvolgiamo il socket standard in un socket TLS
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.sendall(framed)
            logger.info(f"ORU^R01 inviato via mTLS a {nome_dest} ({host}:{porta})")
            return True
        except (ConnectionRefusedError, socket.timeout, OSError, ssl.SSLError) as e:
            if tentativo < MAX_TENTATIVI:
                logger.warning(
                    f"Tentativo {tentativo}/{MAX_TENTATIVI} fallito verso "
                    f"{nome_dest} ({host}:{porta}): {e} — riprovo tra {PAUSA_RETRY_S}s"
                )
                time.sleep(PAUSA_RETRY_S)
            else:
                logger.error(
                    f"INVIO FALLITO definitivamente verso {nome_dest} "
                    f"({host}:{porta}) dopo {MAX_TENTATIVI} tentativi: {e}"
                )
    return False

def esegui_ciclo_fase_7():
    hl7_text, accession_number = genera_referto_casuale()

    logger.info("=" * 55)
    logger.info(f"NUOVO REFERTO — Accession Number: {accession_number}")
    logger.info("=" * 55)
    
    for riga in hl7_text.replace("\r", "\n").splitlines():
        logger.info(riga)

    parsed     = parse_message(hl7_text)
    conclusion = get_field(get_obx_by_codice(parsed, "CONCLUSION"), 5)
    logger.info(f"CONCLUSION inviato: {conclusion}")
    logger.info("-" * 55)

    framed = wrap_mllp(hl7_text)
    invia_con_retry(framed, PACS_HOST, PACS_PORT, "PACS")
    invia_con_retry(framed, HIS_HOST,  HIS_PORT,  "HIS")

# ---------------------------------------------------------------------------
# Listener Fase 8 (MODIFICATO PER mTLS)
# ---------------------------------------------------------------------------
def ascolta_risposta_orm():
    # 1. Creazione del contesto SSL per il Server
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED # Esige il certificato dal Client (mTLS)
    context.load_cert_chain(certfile=RIS_CERT, keyfile=RIS_KEY)
    context.load_verify_locations(cafile=CA_CERT)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((RIS_LISTEN_HOST, RIS_LISTEN_PORT))
    server_sock.listen(5)

    logger.info(f"In ascolto (mTLS) per ORM^O01 RP su {RIS_LISTEN_HOST}:{RIS_LISTEN_PORT}")

    while True:
        conn, addr = server_sock.accept()
        try:
            # 2. Avvolgiamo la connessione in entrata nel tunnel TLS
            conn_tls = context.wrap_socket(conn, server_side=True)
            raw = conn_tls.recv(65536)
            conn_tls.close()

            if not raw:
                continue

            hl7_text = unwrap_mllp(raw)
            parsed = parse_message(hl7_text)
            logger.info(f"ORM^O01 RP ricevuto via mTLS da {addr}:")
            
            obx_images = get_obx_by_codice(parsed, "IMAGES")
            logger.info(f"URL immagini: {get_field(obx_images, 5)}")
            
        except ssl.SSLError as e:
            logger.error(f"Errore TLS durante la connessione con {addr}: {e}")
        except ValueError as e:
            logger.error(f"Frame MLLP malformato in ricezione da {addr}: {e}")

def main():
    # Prima di avviare, verifica la presenza dei certificati
    if not (os.path.exists(RIS_CERT) and os.path.exists(CA_CERT)):
        logger.error("Certificati mancanti! Creare la cartella 'certs' e generare ca.crt, ris.crt e ris.key.")
        return

    parser = argparse.ArgumentParser(description="RIS Server — Fase 7/8 HL7 (mTLS)")
    parser.add_argument("--once", action="store_true", help="Invia un solo referto e termina")
    parser.add_argument("--intervallo", type=int, default=INTERVALLO_DEFAULT_SECONDI)
    parser.add_argument("--no-listen", action="store_true", help="Non aprire il listener ORM")
    args = parser.parse_args()

    logger.info("RIS Server mTLS avviato")
    
    if not args.no_listen:
        t = threading.Thread(target=ascolta_risposta_orm, daemon=True)
        t.start()

    if args.once:
        esegui_ciclo_fase_7()
        return

    try:
        while True:
            esegui_ciclo_fase_7()
            time.sleep(args.intervallo)
    except KeyboardInterrupt:
        logger.info("Arresto richiesto dall'utente.")

if __name__ == "__main__":
    main()
