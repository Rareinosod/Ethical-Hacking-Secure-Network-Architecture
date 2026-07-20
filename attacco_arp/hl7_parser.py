"""
hl7_parser.py
=============
Libreria condivisa usata da ris_server.py, pacs_server.py e his_server.py.

Centralizza due cose:
1. Il wrapping/unwrapping MLLP (il "trasporto" su cui viaggia il testo HL7 via TCP).
2. Il parsing del testo HL7 in segmenti e campi, con funzioni di accesso semplici.

"""

from datetime import datetime

# ---------------------------------------------------------------------------
# 1. COSTANTI DI TRASPORTO MLLP (Minimal Lower Layer Protocol)
# ---------------------------------------------------------------------------
# Un messaggio HL7 su TCP viene sempre incapsulato così:
#
#   0x0B  +  <testo HL7, segmenti separati da \r>  +  0x1C  +  0x0D

START_BLOCK = b"\x0b"   # VT - inizio messaggio MLLP
END_BLOCK = b"\x1c"      # FS - fine messaggio MLLP
CARRIAGE_RETURN = b"\x0d"  # CR - chiusura del frame

# Porta standard HL7/MLLP usata in tutto il progetto 
DEFAULT_HL7_PORT = 2575


def wrap_mllp(hl7_text: str) -> bytes:
    """
    Prende il testo HL7 (segmenti separati da \r) e lo incapsula nel
    frame MLLP pronto per essere inviato su un socket TCP.
    """
    return START_BLOCK + hl7_text.encode("ascii") + END_BLOCK + CARRIAGE_RETURN


def unwrap_mllp(raw_bytes: bytes) -> str:
    """
    Rimuove i byte di controllo MLLP (0x0B all'inizio, 0x1C 0x0D alla fine)
    e restituisce il testo HL7 puro.

    """
    if not raw_bytes.startswith(START_BLOCK):
        raise ValueError(
            f"Frame MLLP malformato: manca 0x0B di inizio "
            f"(primo byte ricevuto: {raw_bytes[:1]!r})"
        )
    if not raw_bytes.endswith(END_BLOCK + CARRIAGE_RETURN):
        raise ValueError(
            f"Frame MLLP malformato: manca 0x1C 0x0D di fine "
            f"(ultimi byte ricevuti: {raw_bytes[-2:]!r})"
        )
    # Tolgo 1 byte iniziale (0x0B) e 2 byte finali (0x1C 0x0D)
    payload = raw_bytes[1:-2]
    return payload.decode("ascii")


# ---------------------------------------------------------------------------
# 2. PARSING DEL MESSAGGIO HL7 IN SEGMENTI E CAMPI
# ---------------------------------------------------------------------------

def parse_message(hl7_text: str) -> list[list[str]]:
    """
    Divide il testo HL7 in segmenti (righe separate da \r) e ogni segmento
    nei suoi campi (separati da |).

    Esempio di ritorno per la riga:
        "OBX|2|TX|CONCLUSION||Referto: polmonite lobare destra...||"
    ->  ["OBX", "2", "TX", "CONCLUSION", "", "Referto: polmonite...", "", ""]

    Nota sugli indici:
        indice 0 -> nome del segmento ("OBX")
        indice 5 -> valore osservato (es. la CONCLUSION testuale)
    """
    righe = [r for r in hl7_text.split("\r") if r.strip() != ""]
    segmenti = [riga.split("|") for riga in righe]
    return segmenti


def get_segment(parsed: list[list[str]], nome_segmento: str, occorrenza: int = 0):
    """
    Restituisce l'occorrenza N-esima (default: la prima) di un segmento dato
    il suo nome (es. "PID", "OBR", "OBX"). Ritorna None se non trovato.

    Serve perché un messaggio può avere più OBX (es. uno FINDINGS e uno
    CONCLUSION): occorrenza=0 prende il primo OBX, occorrenza=1 il secondo.
    """
    trovati = [seg for seg in parsed if seg and seg[0] == nome_segmento]
    if occorrenza < len(trovati):
        return trovati[occorrenza]
    return None


def get_obx_by_codice(parsed: list[list[str]], codice: str):
    
    for seg in parsed:
        if seg and seg[0] == "OBX" and len(seg) > 3 and seg[3] == codice:
            return seg
    return None


def get_field(segmento: list[str], indice: int) -> str:
    """
    Accesso sicuro a un campo di un segmento già estratto. Ritorna stringa
    vuota se l'indice non esiste, invece di lanciare IndexError: i messaggi
    HL7 reali hanno spesso campi opzionali mancanti in coda.
    """
    if segmento is None:
        return ""
    if indice < len(segmento):
        return segmento[indice]
    return ""


def pretty_print(parsed: list[list[str]]) -> str:
    """
    Rappresentazione leggibile del messaggio, pensata per i log della demo
    (confronto "prima/dopo attacco") e per le slide della presentazione.
    """
    righe_output = []
    for seg in parsed:
        righe_output.append(" | ".join(seg))
    return "\n".join(righe_output)


# ---------------------------------------------------------------------------
# 3. COSTRUZIONE DEI MESSAGGI 
# ---------------------------------------------------------------------------

def timestamp_hl7() -> str:
    """Formato data/ora HL7 standard: YYYYMMDDHHMMSS."""
    return datetime.now().strftime("%Y%m%d%H%M%S")


def build_oru_r01(
    paziente_id: str,
    cognome: str,
    nome: str,
    data_nascita: str,
    sesso: str,
    ordine_id: str,
    accession_number: str,
    esame: str,
    data_esame: str,
    findings: str,
    conclusion: str,
    radiologo_id: str,
    msg_id: str = "MSG006",
) -> str:
    """
    Costruisce un messaggio ORU^R01 (Fase 7 - Refertazione). Il RIS invia questo
    messaggio a PACS e HIS.

    Restituisce il testo HL7 con segmenti separati da \r, pronto per essere
    passato a wrap_mllp().
    """
    msh = f"MSH|^~\\&|RIS|RADIOLOGY|PACS|ARCHIVE|{timestamp_hl7()}||ORU^R01|{msg_id}|P|2.5"
    pid = f"PID|1||{paziente_id}^^^HIS||{cognome}^{nome}||{data_nascita}|{sesso}"
    obr = (
        f"OBR|1|{ordine_id}|{accession_number}|{esame}|||{data_esame}"
        f"|||||||{timestamp_hl7()}||{radiologo_id}"
    )
    obx_findings = f"OBX|1|TX|FINDINGS||{findings}||"
    obx_conclusion = f"OBX|2|TX|CONCLUSION||{conclusion}||"

    segmenti = [msh, pid, obr, obx_findings, obx_conclusion]
    return "\r".join(segmenti)


def build_orm_o01_rp(
    paziente_id: str,
    cognome: str,
    nome: str,
    data_nascita: str,
    sesso: str,
    ordine_id: str,
    accession_number: str,
    esame: str,
    data_esame: str,
    url_immagini: str,
    radiologo_id: str,
    msg_id: str = "MSG007",
) -> str:
    """
    Costruisce un messaggio ORM^O01 RP (Fase 8 - Disponibilità risultati).
    Il PACS invia questo messaggio a RIS e HIS dopo aver ricevuto il referto.
    """
    msh = f"MSH|^~\\&|PACS|ARCHIVE|RIS|RADIOLOGY|{timestamp_hl7()}||ORM^O01|{msg_id}|P|2.5"
    pid = f"PID|1||{paziente_id}^^^HIS||{cognome}^{nome}||{data_nascita}|{sesso}"
    orc = f"ORC|RE|{ordine_id}|||CM||||{timestamp_hl7()}|||{radiologo_id}"
    obr = f"OBR|1|{ordine_id}|{accession_number}|{esame}|||{data_esame}|||||||{timestamp_hl7()}"
    obx_images = f"OBX|1|RP|IMAGES||{url_immagini}||AVAILABLE"

    segmenti = [msh, pid, orc, obr, obx_images]
    return "\r".join(segmenti)


# ---------------------------------------------------------------------------
# Test rapido eseguendo direttamente questo file: python3 hl7_parser.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    msg = build_oru_r01(
        paziente_id="PAZ001",
        cognome="Rossi",
        nome="Mario",
        data_nascita="19800315",
        sesso="M",
        ordine_id="ORD001",
        accession_number="ACC001",
        esame="TAC^TC Torace",
        data_esame="20240115130000",
        findings="Polmoni con addensamento in base destra. Suggestivo per polmonite.",
        conclusion="Referto: polmonite lobare destra. Raccomandato follow-up a 30 giorni.",
        radiologo_id="RAD001",
    )
    print("=== Messaggio HL7 generato (testo puro) ===")
    print(msg.replace("\r", "\n"))  # solo per leggibilità a terminale

    framed = wrap_mllp(msg)
    print("\n=== Frame MLLP (bytes) ===")
    print(framed)

    unwrapped = unwrap_mllp(framed)
    parsed = parse_message(unwrapped)
    print("\n=== Messaggio re-parsato ===")
    print(pretty_print(parsed))

    obx_conclusion = get_obx_by_codice(parsed, "CONCLUSION")
    print("\n=== Campo CONCLUSION estratto (indice 5) ===")
    print(get_field(obx_conclusion, 5))
