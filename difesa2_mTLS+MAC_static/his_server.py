#!/usr/bin/env python3
"""
his_server_tls.py
==============
Simula il sistema HIS (Hospital Information System) con implementazione mTLS.

Versione 2 (Difesa Applicativa):
1. Resta in ascolto sulla porta 2577/TCP richiedendo una connessione crittografata (mTLS).
2. Riceve sia l'ORU^R01 (Fase 7, dal RIS) sia l'ORM^O01 RP (Fase 8, dal PACS).
3. Mantiene una cartella clinica in memoria (dizionario).
4. Esporta automaticamente la cartella clinica su his_cartella_clinica.json.
5. Richiede ai client (RIS e PACS) di autenticarsi tramite i certificati CA.

Esecuzione (dall'interno della cartella V2_Difesa_mTLS):
    python3 his_server_tls.py
"""

import json
import logging
import socket
import ssl
import os
import sys

from hl7_parser import (
    get_field,
    get_obx_by_codice,
    get_segment,
    parse_message,
    pretty_print,
    unwrap_mllp,
)

# ---------------------------------------------------------------------------
# Configurazione di rete
# ---------------------------------------------------------------------------
HIS_LISTEN_HOST = "0.0.0.0"
HIS_LISTEN_PORT = 2577

FILE_EXPORT_JSON = "his_cartella_clinica.json"

# ---------------------------------------------------------------------------
# Configurazione Certificati mTLS
# ---------------------------------------------------------------------------
CERT_DIR = "certs"
HIS_CERT = os.path.join(CERT_DIR, "his.crt")
HIS_KEY  = os.path.join(CERT_DIR, "his.key")
CA_CERT  = os.path.join(CERT_DIR, "ca.crt")

# ---------------------------------------------------------------------------
# Setup logging
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
    logger.info("CARTELLA CLINICA AGGIORNATA (Fase 7 — Referto da RIS via mTLS)")
    logger.info(f"  Paziente   : {nome_completo} (ID: {paziente_id})")
    logger.info(f"  Esame      : {record['esami'][accession_number]['esame']}")
    logger.info(f"  Findings   : {record['esami'][accession_number]['findings']}")
    logger.info(f"  CONCLUSION : {conclusion}")
    logger.info("=" * 55)


def aggiorna_da_orm_o01_rp(parsed):
    """Aggiorna la cartella con la notifica ORM^O01 RP (Fase 8)."""
    pid        = get_segment(parsed, "PID")
    obr        = get_segment(parsed, "OBR")
    obx_images = get_obx_by_codice(parsed, "IMAGES")

    paziente_id      = get_field(pid, 3).split("^")[0]
    accession_number = get_field(obr, 3)

    logger.info("=" * 55)
    logger.info("CARTELLA CLINICA AGGIORNATA (Fase 8 — Disponibilità da PACS via mTLS)")
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
# Gestione connessione in ingresso (MODIFICATO PER mTLS)
# ---------------------------------------------------------------------------

def gestisci_connessione_tls(conn_tls: ssl.SSLSocket, addr):
    """Gestisce una singola connessione TCP sicura in ingresso."""
    logger.info(f"Nuova connessione sicura (mTLS) da {addr}")

    try:
        raw = conn_tls.recv(65536)
    except ssl.SSLError as e:
        logger.error(f"Errore di lettura TLS: {e}")
        return
    finally:
        conn_tls.close()

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
    logger.info("Messaggio HL7 ricevuto in chiaro dal tunnel TLS:")
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
    # Verifica presenza certificati
    if not (os.path.exists(HIS_CERT) and os.path.exists(CA_CERT)):
        logger.error("Certificati mancanti! Generare his.crt e his.key nella cartella 'certs'.")
        sys.exit(1)

    # 1. Creazione contesto SSL come Server
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED # Richiede che RIS e PACS presentino i loro certificati
    context.load_cert_chain(certfile=HIS_CERT, keyfile=HIS_KEY)
    context.load_verify_locations(cafile=CA_CERT)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HIS_LISTEN_HOST, HIS_LISTEN_PORT))
    server_sock.listen(5)

    logger.info("HIS Server mTLS avviato")
    logger.info(f"In ascolto sicuro su {HIS_LISTEN_HOST}:{HIS_LISTEN_PORT} (mTLS/HL7)")
    logger.info(f"Export cartella clinica: {FILE_EXPORT_JSON}")
    logger.info("Log su file: his_log.txt")
    logger.info("Premi CTRL+C per terminare.")

    try:
        while True:
            conn, addr = server_sock.accept()
            try:
                # 2. Wrap del socket in entrata (handshake crittografico)
                conn_tls = context.wrap_socket(conn, server_side=True)
                gestisci_connessione_tls(conn_tls, addr)
            except ssl.SSLError as e:
                logger.error(f"Errore Handshake TLS con {addr}: L'attaccante o un client non autorizzato sta provando a connettersi. Dettagli: {e}")
                conn.close()
    except KeyboardInterrupt:
        logger.info("Arresto richiesto dall'utente.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
