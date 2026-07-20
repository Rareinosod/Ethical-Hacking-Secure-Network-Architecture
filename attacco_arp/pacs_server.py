"""
pacs_server.py
===============
Simula il sistema PACS (Picture Archiving and Communication System).

Versione finale (logging su file + retry):
1. Resta in ascolto sulla porta 2575/TCP (bersaglio dell'attacco C).
2. Per ogni messaggio ORU^R01 ricevuto: decapsula MLLP, parsa HL7, stampa
   e logga i campi principali — in particolare CONCLUSION, il campo che
   cambierà se l'attacco MITM è in corso.
3. Genera e invia l'ORM^O01 RP a RIS e HIS (Fase 8) con retry automatico.
4. Scrive ogni evento su pacs_log.txt (oltre che a schermo).

"""

import logging
import socket
import sys
import time

from hl7_parser import (
    DEFAULT_HL7_PORT,
    build_orm_o01_rp,
    get_field,
    get_obx_by_codice,
    get_segment,
    parse_message,
    pretty_print,
    unwrap_mllp,
    wrap_mllp,
)

# ---------------------------------------------------------------------------
# Configurazione di rete — IP reali dalla topologia Mininet (topo.py)
# Sottogruppo A, segmenti IoMT (10.0.30.0/24) ed Enterprise (10.0.20.0/24)
# ---------------------------------------------------------------------------
PACS_LISTEN_HOST = "0.0.0.0"
PACS_LISTEN_PORT = DEFAULT_HL7_PORT  # 2575 — bersaglio attacco Sottogruppo C

# RIS: stesso segmento IoMT (10.0.30.0/24, switch s4) — traffico L2 diretto,
# NON attraversa R3. Porta 2576 = listener ORM del RIS (Fase 8).
RIS_HOST = "10.0.30.10"   # h_ris — IoMT
RIS_PORT = 2576           # porta dedicata RIS per ricevere ORM (Fase 8)

# HIS: segmento Enterprise (10.0.20.0/24) — il traffico attraversa R3.
# R3 deve avere regola ACCEPT per PACS->HIS su porta 2577.
HIS_HOST = "10.0.20.10"   # his_srv — Enterprise
HIS_PORT = 2577           # porta dedicata dell'HIS

# ---------------------------------------------------------------------------
# Parametri retry
# ---------------------------------------------------------------------------
MAX_TENTATIVI = 3
PAUSA_RETRY_S = 2

# ---------------------------------------------------------------------------
# Setup logging: scrive su schermo e su pacs_log.txt con timestamp.
# ---------------------------------------------------------------------------
logger = logging.getLogger("PACS")
logger.setLevel(logging.DEBUG)
_fmt = logging.Formatter(fmt="%(asctime)s [PACS] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

_ch = logging.StreamHandler()
_ch.setFormatter(_fmt)
logger.addHandler(_ch)

_fh = logging.FileHandler("pacs_log.txt", encoding="utf-8")
_fh.setFormatter(_fmt)
logger.addHandler(_fh)


# ---------------------------------------------------------------------------
# Invio ORM con retry
# ---------------------------------------------------------------------------

def invia_orm_con_retry(framed: bytes, host: str, porta: int, nome_dest: str) -> bool:
    """
    Invia il frame ORM^O01 RP al destinatario con retry automatico.

    Perché il retry è utile qui:
      Il PACS invia la notifica ORM sia al RIS (stesso switch, L2 diretto)
      sia all'HIS (attraverso R3). Il traffico verso HIS attraversa il
      firewall di R3: se la regola iptables non è ancora attiva o se c'è
      instabilità momentanea durante l'ARP poisoning, il primo tentativo
      potrebbe fallire per una ragione transitoria. Il retry dà al sistema
      la possibilità di recuperare autonomamente senza perdere la notifica.
    """
    for tentativo in range(1, MAX_TENTATIVI + 1):
        try:
            with socket.create_connection((host, porta), timeout=5) as sock:
                sock.sendall(framed)
            logger.info(f"ORM^O01 RP inviato a {nome_dest} ({host}:{porta})")
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
# Gestione connessione in ingresso
# ---------------------------------------------------------------------------

def gestisci_connessione(conn: socket.socket, addr):
    """Gestisce una singola connessione TCP in ingresso (un singolo messaggio)."""
    logger.info(f"Nuova connessione da {addr}")

    raw = conn.recv(65536)
    conn.close()

    if not raw:
        logger.warning("Connessione vuota, ignoro.")
        return

    # --- Decapsulamento MLLP -------------------------------------------------
    try:
        hl7_text = unwrap_mllp(raw)
    except ValueError as e:
        logger.error(f"Frame MLLP malformato: {e}")
        logger.error(f"Byte grezzi ricevuti: {raw!r}")
        return

    # --- Parsing e log del messaggio HL7 -------------------------------------
    parsed = parse_message(hl7_text)
    logger.info("Messaggio HL7 ricevuto (vista grezza):")
    for riga in pretty_print(parsed).splitlines():
        logger.info(riga)

    # --- Estrazione campi per il log "parlante" della demo -------------------
    msh           = get_segment(parsed, "MSH")
    pid           = get_segment(parsed, "PID")
    obr           = get_segment(parsed, "OBR")
    obx_findings  = get_obx_by_codice(parsed, "FINDINGS")
    obx_conclusion= get_obx_by_codice(parsed, "CONCLUSION")

    tipo_messaggio   = get_field(msh, 8)
    nome_paziente    = get_field(pid, 5)
    esame            = get_field(obr, 4)
    findings         = get_field(obx_findings, 5)
    conclusion       = get_field(obx_conclusion, 5)
    accession_number = get_field(obr, 3)
    ordine_id        = get_field(obr, 2)
    radiologo_id     = get_field(obr, 16)

    logger.info("=" * 50)
    logger.info(f"RIEPILOGO CAMPI ESTRATTI")
    logger.info(f"  Tipo messaggio : {tipo_messaggio}")
    logger.info(f"  Paziente       : {nome_paziente}")
    logger.info(f"  Esame          : {esame}")
    logger.info(f"  Findings       : {findings}")
    logger.info(f"  CONCLUSION     : {conclusion}")
    logger.info("=" * 50)
    logger.info(">>> CONFRONTARE QUESTO CONCLUSION CON ris_log.txt — <<<")
    logger.info(">>> SE DIVERSO: il payload è stato alterato dall'attacco <<<")

    if tipo_messaggio != "ORU^R01":
        logger.warning(f"Tipo messaggio inatteso ({tipo_messaggio}), non genero ORM.")
        return

    # --- Costruzione e invio ORM^O01 RP (Fase 8) -----------------------------
    paziente_id_puro = get_field(pid, 3).split("^")[0]
    _invia_orm(
        paziente_id=paziente_id_puro,
        cognome_nome=nome_paziente,
        data_nascita=get_field(pid, 7),
        sesso=get_field(pid, 8),
        ordine_id=ordine_id,
        accession_number=accession_number,
        esame=esame,
        radiologo_id=radiologo_id,
    )


def _invia_orm(paziente_id, cognome_nome, data_nascita, sesso,
               ordine_id, accession_number, esame, radiologo_id):
    """
    Costruisce il messaggio ORM^O01 RP e lo invia a RIS e HIS (Fase 8),
    ognuno con retry automatico.
    """
    cognome, nome = cognome_nome.split("^", 1) if "^" in cognome_nome else (cognome_nome, "")

    orm_text = build_orm_o01_rp(
        paziente_id=paziente_id,
        cognome=cognome,
        nome=nome,
        data_nascita=data_nascita,
        sesso=sesso,
        ordine_id=ordine_id,
        accession_number=accession_number,
        esame=esame,
        data_esame=time.strftime("%Y%m%d%H%M%S"),
        url_immagini=f"http://pacs.local/study/{accession_number}",
        radiologo_id=radiologo_id,
    )

    framed = wrap_mllp(orm_text)

    logger.info("Contenuto ORM^O01 RP generato (Fase 8):")
    for riga in orm_text.replace("\r", "\n").splitlines():
        logger.info(riga)

    # Invia a entrambi i destinatari della Fase 8 con retry
    for nome_dest, host, porta in (("RIS", RIS_HOST, RIS_PORT), ("HIS", HIS_HOST, HIS_PORT)):
        invia_orm_con_retry(framed, host, porta, nome_dest)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((PACS_LISTEN_HOST, PACS_LISTEN_PORT))
    server_sock.listen(5)

    logger.info("PACS Server avviato")
    logger.info(f"In ascolto su {PACS_LISTEN_HOST}:{PACS_LISTEN_PORT} (MLLP/HL7)")
    logger.info(f"Fase 8 — destinatari ORM: RIS={RIS_HOST}:{RIS_PORT}  HIS={HIS_HOST}:{HIS_PORT}")
    logger.info("Log su file: pacs_log.txt")
    logger.info("Premi CTRL+C per terminare.")

    try:
        while True:
            conn, addr = server_sock.accept()
            gestisci_connessione(conn, addr)
    except KeyboardInterrupt:
        logger.info("Arresto richiesto dall'utente.")
    finally:
        server_sock.close()
        sys.exit(0)


if __name__ == "__main__":
    main()
