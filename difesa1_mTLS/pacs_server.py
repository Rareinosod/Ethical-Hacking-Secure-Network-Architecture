#!/usr/bin/env python3
"""
pacs_server_tls.py
===============
Simula il sistema PACS (Picture Archiving and Communication System) con mTLS.

Versione 2 (Difesa Applicativa):
- Ascolta connessioni crittografate (Server mTLS) sulla porta 2575.
- Invia le notifiche ORM (Client mTLS) crittografate a RIS e HIS.
"""

import logging
import socket
import sys
import time
import ssl
import os

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
# Configurazione di rete
# ---------------------------------------------------------------------------
PACS_LISTEN_HOST = "0.0.0.0"
PACS_LISTEN_PORT = DEFAULT_HL7_PORT  

RIS_HOST = "10.0.30.10"   
RIS_PORT = 2576           

HIS_HOST = "10.0.20.10"   
HIS_PORT = 2577           

MAX_TENTATIVI = 3
PAUSA_RETRY_S = 2

# ---------------------------------------------------------------------------
# Configurazione Certificati mTLS
# ---------------------------------------------------------------------------
CERT_DIR = "certs"
PACS_CERT = os.path.join(CERT_DIR, "pacs.crt")
PACS_KEY  = os.path.join(CERT_DIR, "pacs.key")
CA_CERT   = os.path.join(CERT_DIR, "ca.crt")

# ---------------------------------------------------------------------------
# Setup logging
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
# Invio ORM con retry (MODIFICATO PER mTLS)
# ---------------------------------------------------------------------------
def invia_orm_con_retry(framed: bytes, host: str, porta: int, nome_dest: str) -> bool:
    # 1. Creazione contesto SSL come Client
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.load_cert_chain(certfile=PACS_CERT, keyfile=PACS_KEY)
    context.check_hostname = False 

    for tentativo in range(1, MAX_TENTATIVI + 1):
        try:
            with socket.create_connection((host, porta), timeout=5) as sock:
                # 2. Wrap del socket per l'invio
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.sendall(framed)
            logger.info(f"ORM^O01 RP inviato via mTLS a {nome_dest} ({host}:{porta})")
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

# ---------------------------------------------------------------------------
# Gestione connessione in ingresso (MODIFICATO PER mTLS)
# ---------------------------------------------------------------------------
def gestisci_connessione_tls(conn_tls: ssl.SSLSocket, addr):
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
        return

    parsed = parse_message(hl7_text)
    
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
    logger.info(f"RIEPILOGO CAMPI ESTRATTI (via mTLS)")
    logger.info(f"  Tipo messaggio : {tipo_messaggio}")
    logger.info(f"  Paziente       : {nome_paziente}")
    logger.info(f"  Esame          : {esame}")
    logger.info(f"  CONCLUSION     : {conclusion}")
    logger.info("=" * 50)

    if tipo_messaggio != "ORU^R01":
        logger.warning(f"Tipo messaggio inatteso ({tipo_messaggio}), non genero ORM.")
        return

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
    
    for nome_dest, host, porta in (("RIS", RIS_HOST, RIS_PORT), ("HIS", HIS_HOST, HIS_PORT)):
        invia_orm_con_retry(framed, host, porta, nome_dest)


def main():
    if not (os.path.exists(PACS_CERT) and os.path.exists(CA_CERT)):
        logger.error("Certificati mancanti! Generare pacs.crt e pacs.key nella cartella 'certs'.")
        sys.exit(1)

    # 1. Creazione contesto SSL come Server
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=PACS_CERT, keyfile=PACS_KEY)
    context.load_verify_locations(cafile=CA_CERT)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((PACS_LISTEN_HOST, PACS_LISTEN_PORT))
    server_sock.listen(5)

    logger.info("PACS Server mTLS avviato")
    logger.info(f"In ascolto su {PACS_LISTEN_HOST}:{PACS_LISTEN_PORT}")

    try:
        while True:
            conn, addr = server_sock.accept()
            try:
                # 2. Wrap del socket in entrata
                conn_tls = context.wrap_socket(conn, server_side=True)
                gestisci_connessione_tls(conn_tls, addr)
            except ssl.SSLError as e:
                logger.error(f"Errore Handshake TLS con {addr}: {e}")
                conn.close()
    except KeyboardInterrupt:
        logger.info("Arresto richiesto dall'utente.")
    finally:
        server_sock.close()
        sys.exit(0)

if __name__ == "__main__":
    main()
