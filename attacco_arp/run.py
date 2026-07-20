#!/usr/bin/env python3
"""
Obiettivo: Inizializzare la topologia di rete, configurare routing e firewall, 
           eseguire test di connettività e avviare l'ambiente di simulazione.

Uso:
    sudo python3 run.py
"""

from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.term import makeTerm
from mininet.node import OVSBridge
import time
import os # Necessario per ricavare i percorsi assoluti
import subprocess

from topo import HospitalTopo
from test_connectivity import esegui_tutti_i_test
import webbrowser  
# Ricava il percorso assoluto della directory corrente
cartella = os.path.dirname(os.path.abspath(__file__))


def configure_routing(net):
    """
    Tabelle di routing statiche sui 3 router e sugli host multi-rotta (DMZ,
    Enterprise). Solo le reti NON direttamente connesse vanno
    aggiunte esplicitamente; quelle direttamente connesse le conosce già
    grazie all'IP assegnato all'interfaccia in topo.py.
    """
    info('*** Configurazione del routing statico\n')

    # R1 (Bordo): Conosce direttamente Internet (192.0.2.0/24) e DMZ (10.0.10.0/24).
    # Deve raggiungere Enterprise (20) e IoMT (30) passando per il router R2.
    net['r1'].cmd('ip route add 10.0.20.0/24 via 10.0.10.2 dev r1-eth1')
    net['r1'].cmd('ip route add 10.0.30.0/24 via 10.0.10.2 dev r1-eth1')

    # R2 (Core): Conosce direttamente DMZ e Enterprise.
    # Invia il traffico Internet verso R1 e il traffico IoMT verso R3.
    net['r2'].cmd('ip route add 192.0.2.0/24 via 10.0.10.1 dev r2-eth0')
    net['r2'].cmd('ip route add 10.0.30.0/24 via 10.0.20.2 dev r2-eth1')

    # R3 (Interno): Conosce direttamente Enterprise e IoMT.
    # Invia tutto il traffico per Internet e DMZ verso R2.
    net['r3'].cmd('ip route add 192.0.2.0/24 via 10.0.20.1 dev r3-eth0')
    net['r3'].cmd('ip route add 10.0.10.0/24 via 10.0.20.1 dev r3-eth0')

    # Host DMZ (WebServer, DB_SQL): due direzioni utili, niente "default".
    # Verso Internet instradano su R1. Verso le reti interne instradano su R2.
    for h in ('web_srv', 'db_sql'):
        net[h].cmd('ip route add 192.0.2.0/24 via 10.0.10.1')
        net[h].cmd('ip route add 10.0.20.0/24 via 10.0.10.2')
        net[h].cmd('ip route add 10.0.30.0/24 via 10.0.10.2')

    # Host Enterprise (HIS, PC_Admin): due direzioni utili.
    # Verso DMZ/Internet instradano su R2. Verso IoMT instradano su R3.
    for h in ('his_srv', 'pc_admin'):
        net[h].cmd('ip route add 192.0.2.0/24 via 10.0.20.1')
        net[h].cmd('ip route add 10.0.10.0/24 via 10.0.20.1')
        net[h].cmd('ip route add 10.0.30.0/24 via 10.0.20.2')

    # NB: pc_ext e gli host IoMT hanno già la rotta di default
    # impostata in topo.py e non serve aggiungere nulla qui.


def run():
    topo = HospitalTopo()
    # switch=OVSBridge + controller=None: gli switch lavorano in modalità
    # "standalone" (come bridge L2 tradizionali), senza bisogno di un
    # controller OpenFlow esterno per definire le regole di inoltro. 
    net = Mininet(topo=topo, switch=OVSBridge, controller=None)
    net.start()

    configure_routing(net)

    # Apre automaticamente i terminali xterm per visualizzare i log di router e host
    hosts_dict = {}
    for host in net.hosts:
        hosts_dict[str(host.name)] = host

    for r in ('r1', 'r2', 'r3'):
        net.terms += makeTerm(net[r])
    for h in hosts_dict.values():
        net.terms += makeTerm(h)

    # Fase 1: Verifica base (Firewall non ancora attivi)
    # In questa fase TUTTI devono raggiungere TUTTI
    info('*** Verifica connettività end-to-end (pingAll)\n')
    net.pingAll()

    # Fase 2: Configurazione sicurezza
    info('*** Applicazione regole iptables (setup_firewall.sh)\n')
    for router in ('r1', 'r2', 'r3'):
        net[router].cmd(
            f'bash {cartella}/setup_firewall.sh {router}'
        )
        info(f'    → {router}: regole applicate\n')

    # Fase 3: Avvio e validazione servizi
    info('*** Avvio server di test in background\n')
  
    # Prima di avviare, killiamo eventuali processi residui delle run precedenti
    # per evitare che i socket rimangano occupati (errore "Address already in use")
    for nodo in ('web_srv', 'h_ris', 'h_pacs', 'his_srv', 'pc_ext'):
        net[nodo].cmd('pkill -f server.py 2>/dev/null; pkill -f echo_server.py 2>/dev/null')
    time.sleep(1)

    # web_srv e pc_ext eseguono il normale web server
    net['web_srv'].cmd(f'python3 {cartella}/server.py > /tmp/web_srv.log 2>&1 &')
    net['pc_ext'].cmd(f'python3 {cartella}/server.py > /tmp/pc_ext.log 2>&1 &')

    # I nodi ospedalieri avviano echo_server.py (server di test) passandogli come argomento la porta 2575
    net['h_ris'].cmd(f'python3 {cartella}/echo_server.py 2575 > /tmp/h_ris.log 2>&1 &')
    net['h_pacs'].cmd(f'python3 {cartella}/echo_server.py 2575 > /tmp/h_pacs.log 2>&1 &')
    net['his_srv'].cmd(f'python3 {cartella}/echo_server.py 2575 > /tmp/his_srv.log 2>&1 &')

    time.sleep(3)  # attesa sufficiente per apertura porte

    # Controllo di integrità: verifica rapida sui socket in ascolto (ss -tlnp)
    for nodo, porta in [('web_srv', 80), ('h_ris', 2575),
                         ('h_pacs', 2575), ('his_srv', 2575), ('pc_ext', 80)]:
        esito = net[nodo].cmd(f'ss -tlnp | grep :{porta}')
        if str(porta) in esito:
            info(f'    ✅ {nodo} in ascolto su :{porta}\n')
        else:
            info(f'    ❌ {nodo} NON in ascolto su :{porta} — '
                 f'controllare /tmp/{nodo}.log\n')

    info('*** Lancio test automatico connettività (test_connectivity.py)\n')
    esegui_tutti_i_test(net)

    # Termina i server fittizi PRIMA di aprire la CLI per liberare la porta 2575. 
    # Se non li fermiamo, avviare i server reali (pacs/ris/his) darebbe 
    # "OSError: [Errno 98] Address already in use".
    info('*** Pulizia server di test (liberazione porte per server HL7 reali)\n')
    cartella_hl7 = cartella # Variabile d'appoggio per i comandi CLI
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


    # Esegue la dashboard con Popen sull'host principale (sistema operativo reale), 
    # fuori dal namespace isolato di Mininet. Questo permette l'accesso da browser a localhost.
    info('*** Avvio dashboard web unificata...\n')
    _dashboard = subprocess.Popen(
        ['python3', f'{cartella}/hospital_dashboard.py'],
        stdout=open('/tmp/dashboard.log', 'w'),     
        stderr=subprocess.STDOUT
    )
    info('*** Dashboard disponibile su http://localhost:8080\n')
    info('*** Apro automaticamente il browser...\n')
    time.sleep(2) # Aspetta 2 secondi per far avviare bene Flask
    webbrowser.open('http://localhost:8080')

    info('*** Avvio CLI Mininet\n')
    CLI(net)

    # Pulizia finale al termine della simulazione (quando l'utente esce dalla CLI)
    _dashboard.terminate() 
    info('*** Arresto della rete\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
