"""
his_server.py
==============
Simula il sistema HIS (Hospital Information System).

1. Resta in ascolto sulla porta 2577/TCP (porta dedicata, separata da PACS).
2. Riceve sia l'ORU^R01 (Fase 7, dal RIS) sia l'ORM^O01 RP (Fase 8, dal PACS).
3. Mantiene una cartella clinica in memoria (dizionario), aggiornata ad ogni
   messaggio ricevuto.
4. Esporta automaticamente la cartella clinica su his_cartella_clinica.json.
5. Scrive ogni evento su his_log.txt (oltre che a schermo).

"""

import json
import logging
import socket

from hl7_parser import (
    get_field,
    get_obx_by_codice,
    get_segment,
    parse_message,
    pretty_print,
    unwrap_mllp,
)

# ---------------------------------------------------------------------------
# Configurazione di rete — HIS ascolta su tutte le interfacce, porta 2577.
# Non ha IP di destinazione: riceve soltanto, non invia.
# ---------------------------------------------------------------------------
HIS_LISTEN_HOST = "0.0.0.0"
HIS_LISTEN_PORT = 2577

FILE_EXPORT_JSON = "his_cartella_clinica.json"

# ---------------------------------------------------------------------------
# Setup logging: scrive su schermo e su his_log.txt con timestamp.
# Il valore di CONCLUSION loggato qui è sempre quello ORIGINALE (arriva
# direttamente dal RIS, non passa per il PACS). Confrontarlo con pacs_log.txt
# permette di vedere immediatamente se e quanto C ha alterato il referto.
# ---------------------------------------------------------------------------
logger = logging.getLogger("HIS")
logger.setLevel(logging.DEBUG)
_fmt = logging.Formatter(fmt="%(asctime)s [HIS] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

_ch = logging.StreamHandler()
_ch.setFormatter(_fmt)
logger.addHandler(_ch)

_fh = logging.FileHandler("his_log.txt", encoding="utf-8")
_fh.setFormatter(_fmt)
logger.addHandler(_fh)

# ---------------------------------------------------------------------------
# Cartella clinica in memoria
#   { paziente_id: { nome_completo, data_nascita, sesso, esami: { acc: {...} } } }
# ---------------------------------------------------------------------------
cartella_clinica = {}


# ---------------------------------------------------------------------------
# Aggiornamento cartella clinica
# ---------------------------------------------------------------------------

def aggiorna_da_oru_r01(parsed):
    """Aggiorna la cartella con i dati del referto ORU^R01 (Fase 7)."""
    pid           = get_segment(parsed, "PID")
    obr           = get_segment(parsed, "OBR")
    obx_findings  = get_obx_by_codice(parsed, "FINDINGS")
    obx_conclusion= get_obx_by_codice(parsed, "CONCLUSION")

    paziente_id  = get_field(pid, 3).split("^")[0]
    nome_completo = get_field(pid, 5)

    record = cartella_clinica.setdefault(paziente_id, {
        "nome_completo": nome_completo,
        "data_nascita":  get_field(pid, 7),
        "sesso":         get_field(pid, 8),
        "esami":         {},
    })

    accession_number = get_field(obr, 3)
    conclusion       = get_field(obx_conclusion, 5)

    record["esami"][accession_number] = {
        "esame":               get_field(obr, 4),
        "findings":            get_field(obx_findings, 5),
        "conclusion":          conclusion,
        "radiologo":           get_field(obr, 16),
        "immagini_disponibili": False,
    }

    logger.info("=" * 55)
    logger.info("CARTELLA CLINICA AGGIORNATA (Fase 7 — Referto da RIS)")
    logger.info(f"  Paziente   : {nome_completo} (ID: {paziente_id})")
    logger.info(f"  Esame      : {record['esami'][accession_number]['esame']}")
    logger.info(f"  Findings   : {record['esami'][accession_number]['findings']}")
    logger.info(f"  CONCLUSION : {conclusion}")
    logger.info("=" * 55)
    logger.info(">>> VALORE ORIGINALE — arriva direttamente dal RIS,     <<<")
    logger.info(">>> NON passa per il PACS. Confrontare con pacs_log.txt <<<")
    logger.info(">>> per verificare se l'attacco ha alterato il referto. <<<")


def aggiorna_da_orm_o01_rp(parsed):
    """Aggiorna la cartella con la notifica ORM^O01 RP (Fase 8)."""
    pid        = get_segment(parsed, "PID")
    obr        = get_segment(parsed, "OBR")
    obx_images = get_obx_by_codice(parsed, "IMAGES")

    paziente_id      = get_field(pid, 3).split("^")[0]
    accession_number = get_field(obr, 3)

    logger.info("=" * 55)
    logger.info("CARTELLA CLINICA AGGIORNATA (Fase 8 — Disponibilità da PACS)")
    logger.info(f"  Paziente     : {paziente_id}")
    logger.info(f"  Accession    : {accession_number}")
    logger.info(f"  URL immagini : {get_field(obx_images, 5)}")
    logger.info(f"  Stato        : {get_field(obx_images, 7)}")

    record = cartella_clinica.get(paziente_id)
    if record is not None and accession_number in record["esami"]:
        record["esami"][accession_number]["immagini_disponibili"] = True
        logger.info(f"  Immagini segnate come disponibili per {accession_number}.")
    else:
        logger.warning(
            f"Nessun referto precedente trovato per paziente {paziente_id} "
            f"/ accession {accession_number}. "
            f"(Probabile race condition: ORM arrivato prima dell'ORU.)"
        )
    logger.info("=" * 55)


def esporta_su_json():
    """Scrive la cartella clinica su file JSON."""
    try:
        with open(FILE_EXPORT_JSON, "w", encoding="utf-8") as f:
            json.dump(cartella_clinica, f, indent=2, ensure_ascii=False)
        logger.info(f"Cartella clinica esportata in {FILE_EXPORT_JSON}")
    except OSError as e:
        logger.error(f"Impossibile scrivere {FILE_EXPORT_JSON}: {e}")


# ---------------------------------------------------------------------------
# Gestione connessione in ingresso
# ---------------------------------------------------------------------------

def gestisci_connessione(conn: socket.socket, addr):
    """Gestisce una singola connessione TCP in ingresso."""
    logger.info(f"Nuova connessione da {addr}")

    raw = conn.recv(65536)
    conn.close()

    if not raw:
        logger.warning("Connessione vuota, ignoro.")
        return

    try:
        hl7_text = unwrap_mllp(raw)
    except ValueError as e:
        logger.error(f"Frame MLLP malformato: {e}")
        logger.error(f"Byte grezzi ricevuti: {raw!r}")
        return

    parsed = parse_message(hl7_text)
    logger.info("Messaggio HL7 ricevuto (vista grezza):")
    for riga in pretty_print(parsed).splitlines():
        logger.info(riga)

    msh            = get_segment(parsed, "MSH")
    tipo_messaggio = get_field(msh, 8)

    if tipo_messaggio == "ORU^R01":
        aggiorna_da_oru_r01(parsed)
    elif tipo_messaggio == "ORM^O01":
        aggiorna_da_orm_o01_rp(parsed)
    else:
        logger.warning(f"Tipo messaggio non gestito: {tipo_messaggio!r}")
        return

    esporta_su_json()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HIS_LISTEN_HOST, HIS_LISTEN_PORT))
    server_sock.listen(5)

    logger.info("HIS Server avviato")
    logger.info(f"In ascolto su {HIS_LISTEN_HOST}:{HIS_LISTEN_PORT} (MLLP/HL7)")
    logger.info(f"Export cartella clinica: {FILE_EXPORT_JSON}")
    logger.info("Log su file: his_log.txt")
    logger.info("Premi CTRL+C per terminare.")

    try:
        while True:
            conn, addr = server_sock.accept()
            gestisci_connessione(conn, addr)
    except KeyboardInterrupt:
        logger.info("Arresto richiesto dall'utente.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
