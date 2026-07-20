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

"""

import argparse
import logging
import random
import socket
import threading
import time

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
# Configurazione di rete — IP reali dalla topologia Mininet (topo.py)
# Sottogruppo A, segmenti IoMT (10.0.30.0/24) ed Enterprise (10.0.20.0/24)
# ---------------------------------------------------------------------------
PACS_HOST = "10.0.30.20"      # h_pacs — segmento IoMT (stesso switch s4 del RIS)
PACS_PORT = DEFAULT_HL7_PORT  # 2575 — porta standard MLLP, bersaglio attacco C

HIS_HOST = "10.0.20.10"       # his_srv — segmento Enterprise (attraversa R3)
HIS_PORT = 2577               # porta dedicata dell'HIS (vedi his_server.py)

RIS_LISTEN_HOST = "0.0.0.0"
RIS_LISTEN_PORT = 2576        # porta su cui il RIS aspetta l'ORM^O01 RP (Fase 8)

INTERVALLO_DEFAULT_SECONDI = 10

# ---------------------------------------------------------------------------
# Parametri retry
# ---------------------------------------------------------------------------
MAX_TENTATIVI = 3    # quante volte riprovare prima di considerare l'invio fallito
PAUSA_RETRY_S = 2    # secondi di attesa tra un tentativo e il successivo

# ---------------------------------------------------------------------------
# Setup logging: scrive su schermo e su file ris_log.txt con timestamp.
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
# Catalogo dati di esempio per referti realistici e variabili
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


# ---------------------------------------------------------------------------
# Generazione referto
# ---------------------------------------------------------------------------

def genera_referto_casuale() -> tuple[str, str]:
    """
    Crea un messaggio ORU^R01 con dati scelti a caso dal catalogo.
    Ritorna (testo_hl7, accession_number).
    """
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
# Invio con retry
# ---------------------------------------------------------------------------

def invia_con_retry(framed: bytes, host: str, porta: int, nome_dest: str) -> bool:
    """
    Tenta di inviare il frame MLLP al destinatario, riprovando fino a
    MAX_TENTATIVI volte in caso di errore transitorio (es. rete momentaneamente
    instabile durante ARP poisoning).

    Ritorna True se l'invio è riuscito, False se tutti i tentativi falliscono.
      Durante l'ARP Poisoning, la cache ARP di RIS e PACS viene avvelenata
      in modo progressivo: nei primi istanti la rete può essere instabile
      (pacchetti persi o ritardati). Un singolo tentativo potrebbe fallire
      per ragioni transitorie non legate a un problema reale di configurazione.
      Il retry evita che un falso negativo venga loggato come errore definitivo.
    """
    for tentativo in range(1, MAX_TENTATIVI + 1):
        try:
            with socket.create_connection((host, porta), timeout=5) as sock:
                sock.sendall(framed)
            logger.info(f"ORU^R01 inviato a {nome_dest} ({host}:{porta})")
            return True
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
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


# ---------------------------------------------------------------------------
# Ciclo principale Fase 7
# ---------------------------------------------------------------------------

def esegui_ciclo_fase_7():
    """Genera un referto e lo invia a PACS e HIS con retry automatico."""
    hl7_text, accession_number = genera_referto_casuale()

    logger.info("=" * 55)
    logger.info(f"NUOVO REFERTO — Accession Number: {accession_number}")
    logger.info("=" * 55)
    for riga in hl7_text.replace("\r", "\n").splitlines():
        logger.info(riga)
    logger.info(">>> VALORE ORIGINALE CONCLUSION (riferimento pre-attacco) <<<")

    from hl7_parser import parse_message, get_obx_by_codice, get_field
    parsed     = parse_message(hl7_text)
    conclusion = get_field(get_obx_by_codice(parsed, "CONCLUSION"), 5)
    logger.info(f"CONCLUSION inviato: {conclusion}")
    logger.info("-" * 55)

    framed = wrap_mllp(hl7_text)
    invia_con_retry(framed, PACS_HOST, PACS_PORT, "PACS")
    invia_con_retry(framed, HIS_HOST,  HIS_PORT,  "HIS")


# ---------------------------------------------------------------------------
# Listener Fase 8 
# ---------------------------------------------------------------------------

def ascolta_risposta_orm():
    """
    Resta in ascolto sulla porta 2576 per l'ORM^O01 RP che il PACS invia
    in Fase 8. Gira in un daemon thread: non blocca il loop di invio.
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((RIS_LISTEN_HOST, RIS_LISTEN_PORT))
    server_sock.listen(5)

    logger.info(f"In ascolto per ORM^O01 RP su {RIS_LISTEN_HOST}:{RIS_LISTEN_PORT}")

    while True:
        conn, addr = server_sock.accept()
        raw = conn.recv(65536)
        conn.close()

        if not raw:
            continue

        try:
            hl7_text = unwrap_mllp(raw)
        except ValueError as e:
            logger.error(f"Frame MLLP malformato in ricezione da {addr}: {e}")
            continue

        parsed = parse_message(hl7_text)
        logger.info(f"ORM^O01 RP ricevuto da {addr}:")
        for riga in pretty_print(parsed).splitlines():
            logger.info(riga)

        obx_images = get_obx_by_codice(parsed, "IMAGES")
        logger.info(f"URL immagini: {get_field(obx_images, 5)}")
        logger.info(f"Stato:        {get_field(obx_images, 7)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="RIS Server — Fase 7/8 HL7")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Invia un solo referto e termina (utile per debug rapido)",
    )
    parser.add_argument(
        "--intervallo",
        type=int,
        default=INTERVALLO_DEFAULT_SECONDI,
        help=f"Secondi tra un referto e il successivo (default: {INTERVALLO_DEFAULT_SECONDI})",
    )
    parser.add_argument(
        "--no-listen",
        action="store_true",
        help="Non aprire il listener ORM (utile per testare solo l'invio)",
    )
    args = parser.parse_args()

    logger.info("RIS Server avviato")
    logger.info(f"Destinatari: PACS={PACS_HOST}:{PACS_PORT}  HIS={HIS_HOST}:{HIS_PORT}")
    logger.info(f"Log su file: ris_log.txt")

    if not args.no_listen:
        t = threading.Thread(target=ascolta_risposta_orm, daemon=True)
        t.start()

    if args.once:
        esegui_ciclo_fase_7()
        return

    logger.info(f"Loop continuo — un referto ogni {args.intervallo} secondi. CTRL+C per fermare.")
    try:
        while True:
            esegui_ciclo_fase_7()
            time.sleep(args.intervallo)
    except KeyboardInterrupt:
        logger.info("Arresto richiesto dall'utente.")


if __name__ == "__main__":
    main()
