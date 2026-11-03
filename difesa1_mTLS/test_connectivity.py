#!/usr/bin/env python3
"""
test_connectivity.py — Fase 3: Verifica automatica delle regole firewall
=========================================================================
Batteria di 18 test che verifica che ogni coppia sorgente→destinazione
si comporti ESATTAMENTE come previsto dalla traccia ufficiale (GruppoD.pdf,
Sezione 1.4).

DISTINZIONE IMPORTANTE tra i due tipi di test:
  - testa_http()  → usa curl (richiesta HTTP GET vera) per i test su porta 80
                    Necessario perché server.py è un server HTTP, non TCP grezzo.
  - testa_tcp()   → usa client.py (TCP grezzo) per i test su porta 2575 (HL7)
                    Coerente con echo_server.py che accetta TCP grezzo.

Ogni test stampa:
  PASS — il traffico si è comportato come atteso
  FAIL — il traffico si è comportato in modo INATTESO

USO (integrato in run.py, dopo aver applicato setup_firewall.sh):
    from test_connectivity import esegui_tutti_i_test
    esegui_tutti_i_test(net)
"""

import socket
import sys

import os # Assicurarsi che il modulo os sia importato

# ── Cartella progetto ────────────────────────────────────────────────────
CARTELLA = os.path.dirname(os.path.abspath(__file__))

# ── Palette colori ANSI ─────────────────────────────────────────────────
VERDE     = '\033[92m'
ROSSO     = '\033[91m'
GIALLO    = '\033[93m'
BLU       = '\033[94m'
RESET     = '\033[0m'
GRASSETTO = '\033[1m'

# ── Indirizzi IP (devono combaciare con topo.py) ────────────────────────
PC_EXT   = '192.0.2.100'
WEB_SRV  = '10.0.10.10'
DB_SQL   = '10.0.10.20'
HIS_SRV  = '10.0.20.10'
PC_ADMIN = '10.0.20.20'
H_RIS    = '10.0.30.10'
H_PACS   = '10.0.30.20'
H_MOD    = '10.0.30.30'
H_ATT    = '10.0.30.99'

# ── Porte ────────────────────────────────────────────────────────────────
PORTA_HTTP  = 80
PORTA_HTTPS = 443
PORTA_HL7_RIS_PACS = 2575   # RIS↔PACS (bersaglio attacco Sottogruppo C)
PORTA_HL7_HIS      = 2577   # HIS (confermata da his_server.py Sottogruppo B)
PORTA_HL7          = PORTA_HL7_RIS_PACS  # alias per compatibilità

# ── Timeout connessione (secondi) ────────────────────────────────────────
TIMEOUT_CONNESSIONE = 5



# ── Contatori globali ────────────────────────────────────────────────────
PASS_COUNT = 0
FAIL_COUNT = 0


# ════════════════════════════════════════════════════════════════════════
# FUNZIONI DI SUPPORTO
# ════════════════════════════════════════════════════════════════════════

def intestazione_blocco(titolo, descrizione_traccia):
    """Stampa un'intestazione visiva per ogni blocco di test."""
    print(f"\n{BLU}{'═' * 65}{RESET}")
    print(f"{BLU}{GRASSETTO}  {titolo}{RESET}")
    print(f"  {descrizione_traccia}")
    print(f"{BLU}{'═' * 65}{RESET}")


def _valuta_esito(atteso_aperto, connesso, errore):
    """Stampa PASS o FAIL e aggiorna i contatori globali."""
    global PASS_COUNT, FAIL_COUNT

    if connesso == atteso_aperto:
        PASS_COUNT += 1
        if atteso_aperto:
            print(f"    {VERDE}{GRASSETTO}✅ PASS{RESET} — Connessione riuscita come previsto.")
        else:
            print(f"    {VERDE}{GRASSETTO}✅ PASS{RESET} — Traffico bloccato (DROP silenzioso) come previsto.")
    else:
        FAIL_COUNT += 1
        if atteso_aperto:
            print(f"    {ROSSO}{GRASSETTO}❌ FAIL{RESET} — Connessione attesa ma BLOCCATA. "
                  f"Controllare regole ACCEPT su iptables. Errore: {errore}")
        else:
            print(f"    {ROSSO}{GRASSETTO}❌ FAIL{RESET} — Connessione attesa BLOCCATA ma è PASSATA. "
                  f"Regola DROP mancante o mal configurata!")


def testa_http(ip_src_label, ip_dst, porta, atteso_aperto, descrizione, net=None):
    """
    Testa una connessione HTTP usando curl.
    Usato per porta 80: server.py è un server HTTP che richiede una vera
    richiesta GET, non TCP grezzo.
    """
    print(f"\n  {GIALLO}▶ TEST HTTP:{RESET} {descrizione}")
    print(f"    Sorgente: {ip_src_label}  →  Destinazione: http://{ip_dst}:{porta}")
    print(f"    Esito atteso: {'✅ CONNESSIONE PERMESSA' if atteso_aperto else '❌ CONNESSIONE BLOCCATA (DROP)'}")

    connesso = False
    errore   = ""

    if net is not None:
        nodo = net.get(ip_src_label)
        cmd  = (f"curl -s --connect-timeout {TIMEOUT_CONNESSIONE} "
                f"--max-time {TIMEOUT_CONNESSIONE} http://{ip_dst}:{porta} 2>&1")
        output = nodo.cmd(cmd)
        connesso = "Hello world" in output or "200" in output
        errore   = output.strip()[:120] if not connesso else ""
    else:
        try:
            import urllib.request
            urllib.request.urlopen(
                f"http://{ip_dst}:{porta}", timeout=TIMEOUT_CONNESSIONE
            )
            connesso = True
        except Exception as e:
            connesso = False
            errore   = str(e)

    _valuta_esito(atteso_aperto, connesso, errore)


def testa_tcp(ip_src_label, ip_dst, porta, atteso_aperto, descrizione, net=None):
    """
    Testa una connessione TCP grezza usando client.py.
    Usato per porta 2575 (HL7): echo_server.py accetta TCP grezzo.
    """
    print(f"\n  {GIALLO}▶ TEST TCP:{RESET} {descrizione}")
    print(f"    Sorgente: {ip_src_label}  →  Destinazione: {ip_dst}:{porta}")
    print(f"    Esito atteso: {'✅ CONNESSIONE PERMESSA' if atteso_aperto else '❌ CONNESSIONE BLOCCATA (DROP)'}")

    connesso = False
    errore   = ""

    if net is not None:
        nodo   = net.get(ip_src_label)
        cmd = f"python3 {CARTELLA}/client.py {ip_dst} {porta} 'TEST firewall' 2>&1"
        output = nodo.cmd(f"timeout {TIMEOUT_CONNESSIONE + 2} {cmd}")
        connesso = "CONNESSIONE RIUSCITA" in output
        errore   = output.strip().split('\n')[-1][:120] if not connesso else ""
    else:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT_CONNESSIONE)
            s.connect((ip_dst, porta))
            s.close()
            connesso = True
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            connesso = False
            errore   = str(e)

    _valuta_esito(atteso_aperto, connesso, errore)


# ════════════════════════════════════════════════════════════════════════
# BATTERIA DI TEST
# ════════════════════════════════════════════════════════════════════════

def esegui_tutti_i_test(net=None):
    """
    Esegue i 18 test di connettività.
    Chiamabile da run.py (con oggetto net) o in standalone.
    """
    global PASS_COUNT, FAIL_COUNT
    PASS_COUNT = 0
    FAIL_COUNT = 0

    print(f"\n{GRASSETTO}{'=' * 65}")
    print(f"  TEST AUTOMATICO REGOLE FIREWALL — Sottogruppo A")
    print(f"  Progetto Gruppo D: Rete Ospedaliera Sicura")
    print(f"{'=' * 65}{RESET}")
    print(f"  Riferimento: GruppoD.pdf Sezione 1.4")
    print(f"  Timeout per test bloccati: {TIMEOUT_CONNESSIONE}s")
    print(f"\n  ⚠️  PREREQUISITI:")
    print(f"  1. setup_firewall.sh applicato su r1, r2, r3")
    print(f"  2. web_srv python3 server.py &")
    print(f"  3. h_ris python3 echo_server.py 2575 &")
    print(f"  4. h_pacs python3 echo_server.py 2575 &")
    print(f"  5. his_srv python3 echo_server.py 2575 &")

    # ════════════════════════════════════════════════════════════════════
    # BLOCCO 1 — R1: Internet ↔ DMZ
    # ════════════════════════════════════════════════════════════════════
    intestazione_blocco(
        "BLOCCO 1 — R1: Internet ↔ DMZ",
        "Da traccia: solo HTTP (80) da Internet verso Web Server (10.0.10.10)"
    )

    testa_http('pc_ext', WEB_SRV, PORTA_HTTP, True,
               "Internet → Web Server (HTTP/80): DEVE passare", net)

    testa_http('pc_ext', DB_SQL, PORTA_HTTP, False,
               "Internet → DB_SQL (HTTP/80): DEVE essere bloccato (non è il Web Server)", net)

    testa_http('pc_ext', HIS_SRV, PORTA_HTTP, False,
               "Internet → HIS Server (HTTP/80): DEVE essere bloccato (Enterprise off-limits)", net)

    testa_tcp('pc_ext', H_RIS, PORTA_HL7, False,
              "Internet → RIS (HL7/2575): DEVE essere bloccato (IoMT off-limits)", net)

    # ════════════════════════════════════════════════════════════════════
    # BLOCCO 2 — R2: DMZ/Internet ↔ Enterprise
    # ════════════════════════════════════════════════════════════════════
    intestazione_blocco(
        "BLOCCO 2 — R2: DMZ/Internet ↔ Enterprise",
        "Da traccia: Enterprise può navigare; DMZ/Internet NON può raggiungere Enterprise"
    )

    testa_http('pc_admin', WEB_SRV, PORTA_HTTP, False,
               "PC_Admin (Enterprise) → Web Server (DMZ/HTTP): DEVE essere bloccato", net)

    testa_http('web_srv', HIS_SRV, PORTA_HTTP, False,
               "Web Server (DMZ) → HIS Server (Enterprise/HTTP): DEVE essere bloccato", net)

    testa_http('pc_admin', PC_EXT, PORTA_HTTP, True,
               "PC_Admin (Enterprise) → Internet (HTTP/80): DEVE passare (navigazione permessa)", net)

    # ════════════════════════════════════════════════════════════════════
    # BLOCCO 3 — R3: Enterprise ↔ IoMT (HL7)
    # ════════════════════════════════════════════════════════════════════
    intestazione_blocco(
        "BLOCCO 3 — R3: Enterprise ↔ IoMT (traffico HL7)",
        "Da traccia: solo HIS↔RIS/PACS su porta 2575. Tutto il resto bloccato."
    )

    testa_tcp('his_srv', H_RIS, PORTA_HL7, True,
              "HIS Server → RIS (HL7/2575): DEVE passare (flusso clinico autorizzato)", net)

    testa_tcp('his_srv', H_PACS, PORTA_HL7, True,
              "HIS Server → PACS (HL7/2575): DEVE passare (flusso clinico autorizzato)", net)

    testa_tcp('his_srv', H_MOD, PORTA_HL7, False,
              "HIS Server → Modality (HL7/2575): DEVE essere bloccato (non autorizzato)", net)

    testa_tcp('pc_admin', H_RIS, PORTA_HL7, False,
              "PC_Admin → RIS (HL7/2575): DEVE essere bloccato (solo HIS può parlare con IoMT)", net)

    testa_tcp('pc_admin', H_PACS, PORTA_HL7, False,
              "PC_Admin → PACS (HL7/2575): DEVE essere bloccato", net)

    testa_tcp('web_srv', H_RIS, PORTA_HL7, False,
              "Web Server (DMZ) → RIS (IoMT/HL7): DEVE essere bloccato", net)

    testa_tcp('pc_ext', H_RIS, PORTA_HL7, False,
              "PC_Ext (Internet) → RIS (IoMT/HL7): DEVE essere bloccato", net)

    # ════════════════════════════════════════════════════════════════════
    # BLOCCO 4 — Robustezza: scenari di bypass
    # ════════════════════════════════════════════════════════════════════
    intestazione_blocco(
        "BLOCCO 4 — Robustezza: scenari di bypass",
        "Verifica che non esistano percorsi alternativi non autorizzati"
    )

    testa_tcp('h_att', HIS_SRV, PORTA_HL7_HIS, False,
              "Attaccante (IoMT) → HIS Server (Enterprise): DEVE essere bloccato", net)

    testa_http('h_att', WEB_SRV, PORTA_HTTP, False,
               "Attaccante (IoMT) → Web Server (DMZ): DEVE essere bloccato", net)

    testa_http('h_att', PC_EXT, PORTA_HTTP, False,
               "Attaccante (IoMT) → Internet: DEVE essere bloccato", net)

    testa_tcp('h_mod', HIS_SRV, PORTA_HL7_HIS, False,
              "Modality (IoMT) → HIS Server: DEVE essere bloccato (solo RIS/PACS autorizzati)", net)

    # ════════════════════════════════════════════════════════════════════
    # RIEPILOGO FINALE
    # ════════════════════════════════════════════════════════════════════
    totale = PASS_COUNT + FAIL_COUNT
    print(f"\n{GRASSETTO}{'=' * 65}")
    print(f"  RIEPILOGO FINALE")
    print(f"{'=' * 65}{RESET}")
    print(f"  Test totali : {totale}")
    print(f"  {VERDE}{GRASSETTO}✅ PASS     : {PASS_COUNT}{RESET}")
    print(f"  {ROSSO}{GRASSETTO}❌ FAIL     : {FAIL_COUNT}{RESET}")

    if FAIL_COUNT == 0:
        print(f"\n  {VERDE}{GRASSETTO}🏆 TUTTI I TEST SUPERATI — Firewall configurato correttamente!{RESET}")
        print(f"  La rete ospedaliera rispetta al 100% i requisiti della traccia.")
    else:
        print(f"\n  {ROSSO}{GRASSETTO}⚠️  {FAIL_COUNT} TEST FALLITI — Verificare le regole iptables.{RESET}")
        print(f"  Controllare 'iptables -L FORWARD -n -v' sul router coinvolto.")

    print(f"{GRASSETTO}{'=' * 65}{RESET}\n")
    return FAIL_COUNT == 0


if __name__ == "__main__":
    print(f"{GIALLO}⚠️  Modalità standalone (senza Mininet).{RESET}")
    print(f"   Per risultati reali, usare run.py che passa l'oggetto net.")
    esegui_tutti_i_test(net=None)
