#!/usr/bin/env python3
"""
run.py — Sottogruppo A: avvio della rete ospedaliera
=====================================================
Fase 1 del piano: avvia la topologia e configura SOLO il routing statico.
Nessuna regola iptables qui — l'obiettivo di questo script è verificare che
TUTTI gli host si raggiungano reciprocamente (pingAll), prima di restringere
il traffico con setup_firewall.sh (Fase 2).

Uso:
    sudo python3 run.py
"""

from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.term import makeTerm
from mininet.node import OVSBridge
import time
import os # Aggiunto modulo os
import subprocess

from topo import HospitalTopo
from test_connectivity import esegui_tutti_i_test
import webbrowser  
cartella = os.path.dirname(os.path.abspath(__file__))


def configure_routing(net):
    """
    Tabelle di routing statiche sui 3 router e sugli host multi-rotta (DMZ,
    Enterprise). Stesso principio della tabella di routing vista a lezione:
    per ogni dispositivo, solo le reti NON direttamente connesse vanno
    aggiunte esplicitamente; quelle direttamente connesse le conosce già
    grazie all'IP assegnato all'interfaccia.
    """
    info('*** Configurazione del routing statico\n')

    # ── R1: conosce direttamente Internet (192.0.2.0/24) e DMZ (10.0.10.0/24)
    #     Deve raggiungere Enterprise e IoMT passando per R2.
    net['r1'].cmd('ip route add 10.0.20.0/24 via 10.0.10.2 dev r1-eth1')
    net['r1'].cmd('ip route add 10.0.30.0/24 via 10.0.10.2 dev r1-eth1')

    # ── R2: conosce direttamente DMZ e Enterprise.
    #     Deve raggiungere Internet passando per R1 e IoMT passando per R3.
    net['r2'].cmd('ip route add 192.0.2.0/24 via 10.0.10.1 dev r2-eth0')
    net['r2'].cmd('ip route add 10.0.30.0/24 via 10.0.20.2 dev r2-eth1')

    # ── R3: conosce direttamente Enterprise e IoMT.
    #     Deve raggiungere Internet e DMZ passando per R2.
    net['r3'].cmd('ip route add 192.0.2.0/24 via 10.0.20.1 dev r3-eth0')
    net['r3'].cmd('ip route add 10.0.10.0/24 via 10.0.20.1 dev r3-eth0')

    # ── Host DMZ (WebServer, DB_SQL): due direzioni utili, niente "default".
    #     Verso Internet → R1. Verso Enterprise/IoMT → R2.
    for h in ('web_srv', 'db_sql'):
        net[h].cmd('ip route add 192.0.2.0/24 via 10.0.10.1')
        net[h].cmd('ip route add 10.0.20.0/24 via 10.0.10.2')
        net[h].cmd('ip route add 10.0.30.0/24 via 10.0.10.2')

    # ── Host Enterprise (HIS, PC_Admin): due direzioni utili.
    #     Verso DMZ/Internet → R2. Verso IoMT → R3.
    for h in ('his_srv', 'pc_admin'):
        net[h].cmd('ip route add 192.0.2.0/24 via 10.0.20.1')
        net[h].cmd('ip route add 10.0.10.0/24 via 10.0.20.1')
        net[h].cmd('ip route add 10.0.30.0/24 via 10.0.20.2')

    # NB: pc_ext (default via R1) e gli host IoMT (default via R3) hanno
    # già la rotta di default impostata in topo.py: per loro basta una sola
    # direzione "verso il resto della rete", quindi un defaultRoute è
    # sufficiente e non serve aggiungere nulla qui.


def run():
    topo = HospitalTopo()
    # switch=OVSBridge + controller=None: gli switch lavorano in modalità
    # "standalone" (come bridge L2 tradizionali), senza bisogno di un
    # controller OpenFlow esterno. È lo stesso fallback che il comando
    # `mn` da riga di comando applica automaticamente.
    net = Mininet(topo=topo, switch=OVSBridge, controller=None)
    net.start()

    configure_routing(net)

    # ── Apertura terminali per ogni nodo (router + host) ────────────────
    hosts_dict = {}
    for host in net.hosts:
        hosts_dict[str(host.name)] = host

    for r in ('r1', 'r2', 'r3'):
        net.terms += makeTerm(net[r])
    for h in hosts_dict.values():
        net.terms += makeTerm(h)

    # ── Verifica di connettività completa (Fase 1, nessun firewall) ─────
    # In questa fase TUTTI devono raggiungere TUTTI: è la baseline su cui
    # poi applicheremo le restrizioni di iptables nella Fase 2.
    info('*** Verifica connettività end-to-end (pingAll)\n')
    net.pingAll()

    # ── Applica le regole iptables su ciascun router ─────────────────────
    # Stesso effetto di: r1 bash setup_firewall.sh r1
    # ma automatizzato per la demo (niente comandi manuali necessari)
    info('*** Applicazione regole iptables (setup_firewall.sh)\n')
    for router in ('r1', 'r2', 'r3'):
        net[router].cmd(
            f'bash {cartella}/setup_firewall.sh {router}'
        )
        info(f'    → {router}: regole applicate\n')

    # ── Avvia i server di test in background ─────────────────────────────
    # Prima di avviare, killiamo eventuali processi residui per evitare
    # "Address already in use" (il problema più comune tra sessioni diverse)
    info('*** Avvio server di test in background\n')
  

    for nodo in ('web_srv', 'h_ris', 'h_pacs', 'his_srv', 'pc_ext'):
        net[nodo].cmd('pkill -f server.py 2>/dev/null; pkill -f echo_server.py 2>/dev/null')
    time.sleep(1)

    net['web_srv'].cmd(f'python3 {cartella}/server.py > /tmp/web_srv.log 2>&1 &')
    net['h_ris'].cmd(f'python3 {cartella}/echo_server.py 2575 > /tmp/h_ris.log 2>&1 &')
    net['h_pacs'].cmd(f'python3 {cartella}/echo_server.py 2575 > /tmp/h_pacs.log 2>&1 &')
    net['his_srv'].cmd(f'python3 {cartella}/echo_server.py 2575 > /tmp/his_srv.log 2>&1 &')
    net['pc_ext'].cmd(f'python3 {cartella}/server.py > /tmp/pc_ext.log 2>&1 &')

    time.sleep(3)  # attesa sufficiente per apertura porte

    # Verifica che i server siano effettivamente in ascolto
    for nodo, porta in [('web_srv', 80), ('h_ris', 2575),
                         ('h_pacs', 2575), ('his_srv', 2575), ('pc_ext', 80)]:
        esito = net[nodo].cmd(f'ss -tlnp | grep :{porta}')
        if str(porta) in esito:
            info(f'    ✅ {nodo} in ascolto su :{porta}\n')
        else:
            info(f'    ❌ {nodo} NON in ascolto su :{porta} — '
                 f'controllare /tmp/{nodo}.log\n')

    # ── Batteria di test automatica (Fase 3) ─────────────────────────────
    # Ora il test gira dall'INTERNO dei namespace Mininet → risultati reali
    info('*** Lancio test automatico connettività (test_connectivity.py)\n')
    esegui_tutti_i_test(net)

    # ── Ferma i server di test PRIMA di aprire la CLI ────────────────────
    # echo_server.py e server.py occupano le stesse porte (2575, 2577, 80)
    # dei server HL7 reali del Sottogruppo B. Se non li fermiamo, avviare
    # pacs_server.py / ris_server.py / his_server.py dalla CLI darebbe
    # "OSError: [Errno 98] Address already in use".
    info('*** Pulizia server di test (liberazione porte per server HL7 reali)\n')
    cartella_hl7 = cartella
    for nodo in ('h_ris', 'h_pacs', 'his_srv'):
        net[nodo].cmd('pkill -f echo_server.py 2>/dev/null')
    time.sleep(1)
    info('    ✅ Porte 2575/2577 liberate — server HL7 reali pronti\n')
    info('\n')
    info('*** ═══════════════════════════════════════════════════════════\n')
    info('*** RETE PRONTA — avvia i server HL7 reali dalla CLI Mininet:\n')
    info('***\n')
    info(f'***   his_srv python3 {cartella_hl7}/his_server.py &\n')
    info(f'***   h_pacs  python3 {cartella_hl7}/pacs_server.py &\n')
    info(f'***   h_ris   python3 {cartella_hl7}/ris_server.py &\n')
    info('***\n')
    info(f'*** Per i log: his_srv tail -f {cartella_hl7}/his_log.txt\n')
    info(f'***             h_pacs  tail -f {cartella_hl7}/pacs_log.txt\n')
    info('*** ═══════════════════════════════════════════════════════════\n')
    info('\n')


    # ── Avvio dashboard web unificata (gira su Kali, non dentro Mininet) ─────
    # hospital_dashboard.py legge i file di log dei server HL7 in tempo reale
    # e serve una SPA con 3 tab (RIS / PACS / HIS) accessibile dal browser.
    info('*** Avvio dashboard web unificata...\n')
    _dashboard = subprocess.Popen(
        ['python3', f'{cartella}/hospital_dashboard.py'],
        stdout=open('/tmp/dashboard.log', 'w'),
        stderr=subprocess.STDOUT
    )
    info('*** Dashboard disponibile su http://localhost:8080\n')
    # --- NUOVE RIGHE DA AGGIUNGERE ---
    info('*** Apro automaticamente il browser...\n')
    time.sleep(2) # Aspetta 2 secondi per far avviare bene Flask
    webbrowser.open('http://localhost:8080')
    # ---------------------------------

    info('*** Avvio CLI Mininet\n')
    CLI(net)

    _dashboard.terminate()  # ferma la dashboard quando si esce da Mininet
    info('*** Arresto della rete\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
