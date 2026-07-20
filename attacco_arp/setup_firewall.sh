#!/bin/bash
# ============================================================================
# Script di configurazione iptables (Fase 2 - Firewall Perimetrale)
# ============================================================================
# Implementa le regole di filtraggio per i router R1, R2 e R3 come definito
# dalla traccia ufficiale (Sezione 1.4). In caso di discrepanze documentali,
# prevale il vincolo di massima sicurezza delineato nelle specifiche principali.
#
# USO:
#   Da eseguire all'interno del namespace di ciascun router passandone il
#   nome come argomento (necessario poiché l'hostname Linux non cambia nei
#   nodi Mininet):
#
#       r1 bash setup_firewall.sh r1
#       r2 bash setup_firewall.sh r2
#       r3 bash setup_firewall.sh r3
#
# PRINCIPIO ARCHITETTURALE:
#   Si configurano firewall perimetrali di transito (catena FORWARD).
#   La policy di default è DROP (Zero Trust): tutto il traffico è bloccato
#   salvo esplicita regola di ACCEPT.
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

# Porte HL7 per il traffico clinico (Definite nelle specifiche di integrazione):
#   2575: Porta di ascolto del PACS (ricezione messaggi ORU^R01 dal RIS).
#         Nota: il traffico RIS <-> PACS è di livello L2 (switch s4) e non passa
#         dal firewall. Le regole in R3 servono per le comunicazioni HIS -> RIS/PACS.
#   2577: Porta di ascolto dell'HIS. Il traffico di ritorno (RIS/PACS -> HIS)
#         attraversa R3 risalendo dalla rete IoMT verso l'Enterprise.
HL7_PORT_RIS_PACS=2575
HL7_PORT_HIS=2577

# ── Validazione Input ──────────────────────────────────────────────────────
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
# R1 — Confine Internet ↔ DMZ
# ============================================================================
# Policy:
#  - Default: DROP.
#  - Ingress (da Internet): consentito solo HTTP/HTTPS verso il Web Server.
#  - Egress (verso Internet): consentita la navigazione dalla rete Enterprise.
#  - Protezione: le reti Enterprise e IoMT sono rigorosamente inaccessibili
#    dall'esterno.
# ============================================================================
if [ "$ROUTER_NAME" = "r1" ]; then

    echo "*** Pulizia regole precedenti sulla chain FORWARD"
    # L'aggiunta di "|| true" previene l'interruzione causata da set -e se la catena è già vuota
    iptables -F FORWARD || true

    echo "*** Policy di default: DROP"
    iptables -P FORWARD DROP

    echo "*** [1] Traffico di ritorno per connessioni già stabilite (Stateful Inspection)"
    # Fondamentale: senza questa regola, i pacchetti di risposta alle sessioni 
    # autorizzate verrebbero droppati, impedendo qualsiasi connessione.
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    echo "*** [2] Internet -> Web Server (DMZ): abilitazione HTTP/HTTPS"
    iptables -A FORWARD -s "$NET_INTERNET" -d "$WEB_SRV" \
        -p tcp --dport "$HTTP_PORT" -m state --state NEW -j ACCEPT
    iptables -A FORWARD -s "$NET_INTERNET" -d "$WEB_SRV" \
        -p tcp --dport "$HTTPS_PORT" -m state --state NEW -j ACCEPT

    echo "*** [3] Enterprise -> Internet: abilitazione navigazione web in uscita"
    # Il traffico in uscita dall'Enterprise deve attraversare R1 per raggiungere Internet.
    iptables -A FORWARD -s "$NET_ENTERPRISE" -d "$NET_INTERNET" \
        -p tcp --dport "$HTTP_PORT" -m state --state NEW -j ACCEPT
    iptables -A FORWARD -s "$NET_ENTERPRISE" -d "$NET_INTERNET" \
        -p tcp --dport "$HTTPS_PORT" -m state --state NEW -j ACCEPT

    echo "*** [4] Traffico non autorizzato bloccato in automatico (Policy DROP)"
    # Nessuna regola esplicita per Enterprise/IoMT da Internet garantisce l'isolamento.

    echo "*** Regole attive su R1:"
    iptables -L FORWARD -n -v --line-numbers
fi

# ============================================================================
# R2 — Confine DMZ ↔ Enterprise
# ============================================================================
# Policy:
#  - Default: DROP.
#  - Sicurezza rigida: NESSUNA connessione proveniente da Internet o dalla DMZ
#    può iniziare una sessione verso la rete Enterprise.
#  - Egress: consentito il transito del traffico Enterprise diretto verso
#    Internet (HTTP/HTTPS), che dovrà poi attraversare R1.
# ============================================================================
if [ "$ROUTER_NAME" = "r2" ]; then

    echo "*** Pulizia regole precedenti sulla chain FORWARD"
    iptables -F FORWARD || true

    echo "*** Policy di default: DROP"
    iptables -P FORWARD DROP

    echo "*** [1] Traffico di ritorno per connessioni già stabilite (Stateful Inspection)"
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    echo "*** [2] Enterprise -> Internet: transito navigazione HTTP/HTTPS"
    iptables -A FORWARD -s "$NET_ENTERPRISE" -d "$NET_INTERNET" \
        -p tcp --dport "$HTTP_PORT" -m state --state NEW -j ACCEPT
    iptables -A FORWARD -s "$NET_ENTERPRISE" -d "$NET_INTERNET" \
        -p tcp --dport "$HTTPS_PORT" -m state --state NEW -j ACCEPT

    echo "*** [3] Protezione Enterprise: blocco connessioni in ingresso da DMZ/Internet"
    echo "    (Gestito in automatico dalla policy DROP)"

    echo "*** Regole attive su R2:"
    iptables -L FORWARD -n -v --line-numbers
fi

# ============================================================================
# R3 — Confine Enterprise ↔ IoMT
# ============================================================================
# Policy:
#  - Default: DROP.
#  - Isolamento: l'accesso alla rete IoMT è precluso a PC Amministrativi, 
#    host DMZ e nodi Internet.
#  - Traffico clinico: consentita unicamente la comunicazione bidirezionale 
#    strettamente necessaria (HL7) tra HIS (Enterprise) e RIS/PACS (IoMT).
# ============================================================================
if [ "$ROUTER_NAME" = "r3" ]; then

    echo "*** Pulizia regole precedenti sulla chain FORWARD"
    iptables -F FORWARD || true

    echo "*** Policy di default: DROP"
    iptables -P FORWARD DROP

    echo "*** [1] Traffico di ritorno per connessioni già stabilite (Stateful Inspection)"
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    echo "*** [2] HIS -> RIS: Autorizzazione traffico clinico (HL7)"
    iptables -A FORWARD -s "$HIS_SRV" -d "$RIS_SRV" \
        -p tcp --dport "$HL7_PORT_RIS_PACS" -m state --state NEW -j ACCEPT

    echo "*** [3] HIS -> PACS: Autorizzazione traffico clinico (HL7)"
    iptables -A FORWARD -s "$HIS_SRV" -d "$PACS_SRV" \
        -p tcp --dport "$HL7_PORT_RIS_PACS" -m state --state NEW -j ACCEPT

    echo "*** [4] RIS -> HIS: Autorizzazione flusso di rientro (HL7)"
    iptables -A FORWARD -s "$RIS_SRV" -d "$HIS_SRV" \
        -p tcp --dport "$HL7_PORT_HIS" -m state --state NEW -j ACCEPT

    echo "*** [5] PACS -> HIS: Autorizzazione flusso di rientro (HL7)"
    iptables -A FORWARD -s "$PACS_SRV" -d "$HIS_SRV" \
        -p tcp --dport "$HL7_PORT_HIS" -m state --state NEW -j ACCEPT

    echo "*** [6] Drop e Logging del traffico non autorizzato verso IoMT"
    echo "    (PC_Admin, DMZ e Internet sono isolati dai dispositivi medici)"
    iptables -A FORWARD -j LOG --log-prefix "R3-DROP: "
    # NOTA: La regola di drop esplicita è superflua grazie alla policy di default.

    echo "*** Regole attive su R3:"
    iptables -L FORWARD -n -v --line-numbers
fi

echo "============================================================"
echo " Configurazione completata su $ROUTER_NAME"
echo "============================================================"