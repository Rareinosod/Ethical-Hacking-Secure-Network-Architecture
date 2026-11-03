#!/bin/bash
# ============================================================================
# setup_firewall.sh — Sottogruppo A: regole iptables (Fase 2)
# ============================================================================
# Implementa ESATTAMENTE le regole della Sezione 1.4 della traccia ufficiale
# (GruppoD.pdf). Dove il Piano_Progetto_GruppoD_v2 e la traccia ufficiale
# sembravano in contraddizione (vedi nota su R2 più sotto), si è seguita la
# traccia ufficiale, che è la fonte autorevole per la valutazione.
#
# USO:
#   Questo stesso file va eseguito DENTRO ciascun router (r1, r2, r3),
#   passando il nome del router come primo argomento (necessario perché
#   dentro Mininet l'hostname Linux reale resta sempre quello della VM,
#   non cambia per nodo — quindi non possiamo rilevarlo automaticamente):
#
#       r1 bash setup_firewall.sh r1
#       r2 bash setup_firewall.sh r2
#       r3 bash setup_firewall.sh r3
#
# PRINCIPIO GENERALE (da lezione):
#   Questi sono firewall PERIMETRALI (i pacchetti li attraversano, non sono
#   diretti al router stesso) → le regole vanno nella catena FORWARD, non in
#   INPUT/OUTPUT. La policy di default è DROP: tutto va bloccato a meno che
#   non sia esplicitamente permesso.
# ============================================================================

set -e  # interrompe lo script al primo errore, per non lasciare un firewall a metà

# ── Indirizzi della topologia (devono combaciare con topo.py) ──────────────
NET_INTERNET="192.0.2.0/24"
NET_DMZ="10.0.10.0/24"
NET_ENTERPRISE="10.0.20.0/24"
NET_IOMT="10.0.30.0/24"

WEB_SRV="10.0.10.10"      # Web Server in DMZ
HIS_SRV="10.0.20.10"      # HIS Server in Enterprise
RIS_SRV="10.0.30.10"      # RIS in IoMT
PACS_SRV="10.0.30.20"     # PACS in IoMT

# ── Porte ────────────────────────────────────────────────────────────────
HTTP_PORT=80
HTTPS_PORT=443

# Porte HL7 — contratto tecnico cross-gruppo CONFERMATO con Sottogruppo B:
#
#   HL7_PORT_RIS_PACS = 2575
#     Porta su cui PACS ascolta (riceve ORU^R01 da RIS, Fase 7).
#     Bersaglio attacco ARP Poisoning (Sottogruppo C).
#     NOTA: RIS<->PACS non attraversano R3 (stesso switch s4, traffico L2).
#     Le regole HIS->RIS e HIS->PACS usano questa porta perche HIS e in
#     Enterprise e DEVE attraversare R3.
#
#   HL7_PORT_HIS = 2577
#     Porta su cui HIS ascolta (riceve da RIS e PACS).
#     CONFERMATA da his_server.py del Sottogruppo B.
#     RIS->HIS e PACS->HIS attraversano R3 (IoMT->Enterprise).
HL7_PORT_RIS_PACS=2575
HL7_PORT_HIS=2577

# ── Validazione Input (Spostata in alto per correttezza logica) ────────────
if [ -z "$1" ]; then
    echo "ERRORE: specifica il nome del router come argomento."
    echo "Uso: bash setup_firewall.sh r1   (oppure r2, r3)"
    exit 1
fi

ROUTER_NAME="$1"

if [ "$ROUTER_NAME" != "r1" ] && [ "$ROUTER_NAME" != "r2" ] && [ "$ROUTER_NAME" != "r3" ]; then
    echo "ERRORE: questo script va eseguito solo su r1, r2 o r3."
    echo "Hostname rilevato: $ROUTER_NAME"
    exit 1
fi

echo "============================================================"
echo " Configurazione iptables su: $ROUTER_NAME"
echo "============================================================"

# ============================================================================
# R1 — confine Internet ↔ DMZ
# ============================================================================
# Regole (da traccia, Sezione 1.4):
#  - Policy di default: DROP
#  - In ingresso da Internet: SOLO HTTP/HTTPS verso il Web Server
#  - Nessuna connessione dall'esterno può raggiungere Enterprise o IoMT
#  - L'Enterprise deve poter navigare su Internet (HTTP/HTTPS in uscita):
#    la traccia dice esplicitamente "R2 (e R1 di conseguenza) devono
#    permettere questo traffico in uscita" — quindi anche R1 deve lasciarlo
#    passare quando arriva da Enterprise diretto verso Internet.
# ============================================================================
if [ "$ROUTER_NAME" = "r1" ]; then

    echo "*** Pulizia regole precedenti sulla chain FORWARD"
    # L'aggiunta di "|| true" previene l'interruzione causata da set -e se la catena è già vuota
    iptables -F FORWARD || true

    echo "*** Policy di default: DROP"
    iptables -P FORWARD DROP

    echo "*** [1] Traffico di ritorno per connessioni già stabilite (stateful)"
    # Fondamentale: senza questa regola nessuna risposta potrebbe mai
    # tornare indietro, perché ogni risposta sarebbe trattata come un
    # pacchetto "nuovo" indipendente dalla policy DROP.
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    echo "*** [2] Internet -> Web Server (DMZ): solo HTTP/HTTPS, solo NEW"
    iptables -A FORWARD -s "$NET_INTERNET" -d "$WEB_SRV" \
        -p tcp --dport "$HTTP_PORT" -m state --state NEW -j ACCEPT
    iptables -A FORWARD -s "$NET_INTERNET" -d "$WEB_SRV" \
        -p tcp --dport "$HTTPS_PORT" -m state --state NEW -j ACCEPT

    echo "*** [3] Enterprise -> Internet: navigazione HTTP/HTTPS in uscita"
    # Il personale Enterprise deve poter navigare; il pacchetto attraversa
    # comunque R1 per uscire verso "Internet" (qui rappresentato da
    # NET_INTERNET / pc_ext), quindi la regola va replicata anche qui.
    iptables -A FORWARD -s "$NET_ENTERPRISE" -d "$NET_INTERNET" \
        -p tcp --dport "$HTTP_PORT" -m state --state NEW -j ACCEPT
    iptables -A FORWARD -s "$NET_ENTERPRISE" -d "$NET_INTERNET" \
        -p tcp --dport "$HTTPS_PORT" -m state --state NEW -j ACCEPT

    echo "*** [4] Tutto il resto: DROP (policy di default, già impostata)"
    # Nessuna regola esplicita per Enterprise/IoMT raggiungibili da Internet:
    # cadono automaticamente sulla policy DROP.

    echo "*** Regole attive su R1:"
    iptables -L FORWARD -n -v --line-numbers
fi

# ============================================================================
# R2 — confine DMZ ↔ Enterprise
# ============================================================================
# Regole (da traccia, Sezione 1.4):
#  - Policy di default: DROP
#  - NESSUNA connessione da Internet o DMZ può aprire sessioni verso
#    Enterprise (regola esplicita e tassativa della traccia ufficiale)
#  - Il personale Enterprise può navigare su Internet via HTTP/HTTPS
#    (questo traffico deve poter attraversare anche R2, non solo R1,
#    perché il pacchetto passa fisicamente da Enterprise attraverso DMZ)
#
#  NOTA SULLA DISCREPANZA COL PIANO: il documento Piano_Progetto_GruppoD_v2
#  riporta nella tabella riassuntiva "DMZ: in uscita HTTP/HTTPS verso
#  Enterprise", che sembrerebbe permettere alla DMZ di iniziare connessioni
#  verso Enterprise. Questo CONTRADDICE la regola esplicita della traccia
#  ufficiale (GruppoD.pdf) appena citata. Si è scelto di seguire la traccia
#  ufficiale, più autorevole: nessuna regola ACCEPT per DMZ->Enterprise è
#  stata inserita. Se in sede d'esame viene chiesto conto di questa scelta,
#  motivarla citando il testo esatto del GruppoD.pdf ("la regola
#  fondamentale è che nessuna connessione proveniente da Internet o dalla
#  DMZ può iniziare una sessione verso l'Enterprise").
# ============================================================================
if [ "$ROUTER_NAME" = "r2" ]; then

    echo "*** Pulizia regole precedenti sulla chain FORWARD"
    iptables -F FORWARD || true

    echo "*** Policy di default: DROP"
    iptables -P FORWARD DROP

    echo "*** [1] Traffico di ritorno per connessioni già stabilite (stateful)"
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    echo "*** [2] Enterprise -> Internet: navigazione HTTP/HTTPS in uscita"
    iptables -A FORWARD -s "$NET_ENTERPRISE" -d "$NET_INTERNET" \
        -p tcp --dport "$HTTP_PORT" -m state --state NEW -j ACCEPT
    iptables -A FORWARD -s "$NET_ENTERPRISE" -d "$NET_INTERNET" \
        -p tcp --dport "$HTTPS_PORT" -m state --state NEW -j ACCEPT

    echo "*** [3] Nessuna regola ACCEPT per Internet/DMZ -> Enterprise"
    echo "    (cade sulla policy di default DROP, come da traccia)"

    echo "*** Regole attive su R2:"
    iptables -L FORWARD -n -v --line-numbers
fi

# ============================================================================
# R3 — confine Enterprise ↔ IoMT
# ============================================================================
# Regole (da traccia, Sezione 1.4):
#  - Policy di default: DROP
#  - Solo traffico clinico tra server autorizzati
#  - HIS (Enterprise) <-> RIS e PACS (IoMT): connessioni in ENTRAMBE le
#    direzioni sono permesse ("e viceversa: RIS e PACS possono contattare
#    l'HIS Server")
#  - PC Amministrativi, host DMZ e Internet NON possono MAI raggiungere
#    IoMT, in nessun caso
# ============================================================================
if [ "$ROUTER_NAME" = "r3" ]; then

    echo "*** Pulizia regole precedenti sulla chain FORWARD"
    iptables -F FORWARD || true

    echo "*** Policy di default: DROP"
    iptables -P FORWARD DROP

    echo "*** [1] Traffico di ritorno per connessioni già stabilite (stateful)"
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    echo "*** [2] HIS -> RIS (traffico clinico HL7)"
    iptables -A FORWARD -s "$HIS_SRV" -d "$RIS_SRV" \
        -p tcp --dport "$HL7_PORT_RIS_PACS" -m state --state NEW -j ACCEPT

    echo "*** [3] HIS -> PACS (traffico clinico HL7)"
    iptables -A FORWARD -s "$HIS_SRV" -d "$PACS_SRV" \
        -p tcp --dport "$HL7_PORT_RIS_PACS" -m state --state NEW -j ACCEPT

    echo "*** [4] RIS -> HIS (viceversa, da traccia)"
    iptables -A FORWARD -s "$RIS_SRV" -d "$HIS_SRV" \
        -p tcp --dport "$HL7_PORT_HIS" -m state --state NEW -j ACCEPT

    echo "*** [5] PACS -> HIS (viceversa, da traccia)"
    iptables -A FORWARD -s "$PACS_SRV" -d "$HIS_SRV" \
        -p tcp --dport "$HL7_PORT_HIS" -m state --state NEW -j ACCEPT

    echo "*** [6] Tutto il resto: DROP (policy di default)"
    echo "    PC_Admin, DMZ e Internet NON possono raggiungere IoMT:"
    echo "    nessuna regola ACCEPT esplicita = automaticamente bloccati."
    iptables -A FORWARD -j LOG --log-prefix "R3-DROP: "
    # NOTA: La regola iptables -A FORWARD -j DROP è stata rimossa qui perché ridondante
    # dato che la policy di default copre già il blocco del traffico rimanente.

    echo "*** Regole attive su R3:"
    iptables -L FORWARD -n -v --line-numbers
fi

echo "============================================================"
echo " Configurazione completata su $ROUTER_NAME"
echo "============================================================"
