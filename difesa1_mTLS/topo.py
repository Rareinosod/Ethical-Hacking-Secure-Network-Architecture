#!/usr/bin/env python3
"""
topo.py — Sottogruppo A: Rete Ospedaliera Sicura
==================================================
Topologia a 4 segmenti / 3 router, fedele alla traccia (Sezione 1.3):

   Internet ──R1── DMZ ──R2── Enterprise ──R3── IoMT
   PC_ext         WebServer     HIS Server        RIS
                  DB_SQL        PC_Admin          PACS
                                                   Modality
                                                   Attaccante

NB: questo file definisce SOLO la struttura della rete (host, switch, router,
link, IP). Le regole iptables vengono applicate separatamente in
setup_firewall.sh (Fase 2), così possiamo testare prima che tutto comunichi
correttamente, poi restringere il traffico.

MAC ADDRESS FISSI
------------------
Di default Mininet genera un MAC casuale per ogni interfaccia ad ogni
`sudo python3 topo.py` (o run.py). Per un progetto di ARP Poisoning questo è
un problema concreto: cambiare MAC ad ogni run rende i log/screenshot delle
ARP table non riproducibili da una demo all'altra, e complica il confronto
"prima/dopo l'attacco" da mettere nelle slide.

Per questo motivo generiamo un MAC deterministico a partire dall'IP di ogni
interfaccia, tramite la funzione mac_from_ip() qui sotto. In questo modo:
- ogni interfaccia ha SEMPRE lo stesso MAC, ad ogni riavvio della rete;
- il MAC è ricavabile "a mano" dall'IP anche in fase di presentazione
  (utile per spiegare a voce cosa sta succedendo nell'ARP poisoning);
- non ci sono collisioni: essendo gli IP univoci nella topologia, e la
  conversione IP->esadecimale biunivoca, lo sono anche i MAC risultanti.
"""

from mininet.topo import Topo
from mininet.node import Node


def mac_from_ip(ip_cidr, prefix='02:00'):
    """
    Genera un MAC address deterministico e fisso a partire dagli ultimi
    4 ottetti di un indirizzo IPv4 (accetta anche notazione CIDR, es.
    '10.0.30.10/24': la maschera viene ignorata).

    Prefisso 02:00 -> primo byte 0x02 = 00000010b:
        - bit I/G (meno significativo) = 0  => indirizzo UNICAST
        - bit U/L (secondo bit)        = 1  => indirizzo "locally
          administered", cioè non assegnato da nessun vendor reale.
    Questo evita per costruzione qualunque collisione con MAC address
    fisici veri (i vendor reali hanno sempre il bit U/L a 0).

    Esempio:
        mac_from_ip('10.0.30.10/24')  -> '02:00:0a:00:1e:0a'
        mac_from_ip('192.0.2.100/24') -> '02:00:c0:00:02:64'

    NB implementativo: per gli host single-homed il MAC va passato con
    mac=... dentro addHost() (lo consuma Node.config()). Per le interfacce
    dei router, invece, va passato con addr1=... a livello di addLink()
    (NON dentro params1={}), perché mininet.link.Link già inoltra
    internamente addr1 come argomento mac= a Intf(): se lo si duplica anche
    dentro params1 si ottiene un
    "TypeError: got multiple values for keyword argument 'mac'".
    """
    ip = ip_cidr.split('/')[0]
    ottetti = ip.split('.')
    if len(ottetti) != 4:
        raise ValueError(f'IP non valido per mac_from_ip: {ip_cidr}')
    ottetti_hex = [f'{int(o):02x}' for o in ottetti]
    return f"{prefix}:{':'.join(ottetti_hex)}"


class LinuxRouter(Node):
    """
    Un host Mininet "normale" diventa un router abilitando l'IP forwarding.
    Ricordiamo dalla lezione: di default il forwarding è a 0, va sempre
    attivato esplicitamente, indipendentemente dalle regole di iptables.
    """

    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


class HospitalTopo(Topo):
    def build(self, **_opts):

        # ──────────────────────────────────────────────────────────────
        # ROUTER (3, come da traccia: R1, R2, R3)
        # ──────────────────────────────────────────────────────────────
        r1 = self.addNode('r1', cls=LinuxRouter, ip=None)
        r2 = self.addNode('r2', cls=LinuxRouter, ip=None)
        r3 = self.addNode('r3', cls=LinuxRouter, ip=None)

        # ──────────────────────────────────────────────────────────────
        # SWITCH (uno per segmento, per riflettere una vera LAN condivisa)
        # ──────────────────────────────────────────────────────────────
        # NB: Mininet deriva l'ID interno dello switch (dpid) dalle cifre
        # finali del nome — per questo i nomi DEVONO terminare con un numero
        # (es. s1, s2...), non con una sigla testuale come "s_dmz".
        sw_internet = self.addSwitch('s1')   # segmento Internet
        sw_dmz       = self.addSwitch('s2')  # segmento DMZ
        sw_ent       = self.addSwitch('s3')  # segmento Enterprise
        sw_iomt      = self.addSwitch('s4')  # segmento IoMT

        # ──────────────────────────────────────────────────────────────
        # HOST — segmento INTERNET (192.0.2.0/24)
        # ──────────────────────────────────────────────────────────────
        pc_ext = self.addHost('pc_ext', ip='192.0.2.100/24',
                               mac=mac_from_ip('192.0.2.100/24'),
                               defaultRoute='via 192.0.2.1')

        # ──────────────────────────────────────────────────────────────
        # HOST — segmento DMZ (10.0.10.0/24)
        # ──────────────────────────────────────────────────────────────
        # NB: niente defaultRoute qui. In DMZ ci sono due direzioni utili
        # (Internet via R1, Enterprise/IoMT via R2): le rotte esplicite
        # vengono aggiunte in run.py, non qui nella topologia.
        web_server = self.addHost('web_srv', ip='10.0.10.10/24',
                                   mac=mac_from_ip('10.0.10.10/24'))
        db_sql     = self.addHost('db_sql', ip='10.0.10.20/24',
                                   mac=mac_from_ip('10.0.10.20/24'))

        # ──────────────────────────────────────────────────────────────
        # HOST — segmento ENTERPRISE (10.0.20.0/24)
        # ──────────────────────────────────────────────────────────────
        his_server = self.addHost('his_srv', ip='10.0.20.10/24',
                                   mac=mac_from_ip('10.0.20.10/24'))
        pc_admin   = self.addHost('pc_admin', ip='10.0.20.20/24',
                                   mac=mac_from_ip('10.0.20.20/24'))

        # ──────────────────────────────────────────────────────────────
        # HOST — segmento IoMT (10.0.30.0/24)
        # ──────────────────────────────────────────────────────────────
        # Tutti sullo stesso switch (s_iomt): è il requisito esplicito
        # della traccia, indispensabile per l'ARP Poisoning del Sottogruppo C.
        ris  = self.addHost('h_ris', ip='10.0.30.10/24',
                             mac=mac_from_ip('10.0.30.10/24'),
                             defaultRoute='via 10.0.30.1')
        pacs = self.addHost('h_pacs', ip='10.0.30.20/24',
                             mac=mac_from_ip('10.0.30.20/24'),
                             defaultRoute='via 10.0.30.1')
        modality = self.addHost('h_mod', ip='10.0.30.30/24',
                                 mac=mac_from_ip('10.0.30.30/24'),
                                 defaultRoute='via 10.0.30.1')
        attaccante = self.addHost('h_att', ip='10.0.30.99/24',
                                   mac=mac_from_ip('10.0.30.99/24'),
                                   defaultRoute='via 10.0.30.1')

        # ──────────────────────────────────────────────────────────────
        # LINK — segmento Internet
        # ──────────────────────────────────────────────────────────────
        self.addLink(pc_ext, sw_internet)
        self.addLink(r1, sw_internet,
                     intfName1='r1-eth0',
                     addr1=mac_from_ip('192.0.2.1/24'),
                     params1={'ip': '192.0.2.1/24'})

        # ──────────────────────────────────────────────────────────────
        # LINK — segmento DMZ (qui convergono R1 e R2)
        # ──────────────────────────────────────────────────────────────
        self.addLink(r1, sw_dmz,
                     intfName1='r1-eth1',
                     addr1=mac_from_ip('10.0.10.1/24'),
                     params1={'ip': '10.0.10.1/24'})
        self.addLink(r2, sw_dmz,
                     intfName1='r2-eth0',
                     addr1=mac_from_ip('10.0.10.2/24'),
                     params1={'ip': '10.0.10.2/24'})
        self.addLink(web_server, sw_dmz)
        self.addLink(db_sql, sw_dmz)

        # ──────────────────────────────────────────────────────────────
        # LINK — segmento Enterprise (qui convergono R2 e R3)
        # ──────────────────────────────────────────────────────────────
        self.addLink(r2, sw_ent,
                     intfName1='r2-eth1',
                     addr1=mac_from_ip('10.0.20.1/24'),
                     params1={'ip': '10.0.20.1/24'})
        self.addLink(r3, sw_ent,
                     intfName1='r3-eth0',
                     addr1=mac_from_ip('10.0.20.2/24'),
                     params1={'ip': '10.0.20.2/24'})
        self.addLink(his_server, sw_ent)
        self.addLink(pc_admin, sw_ent)

        # ──────────────────────────────────────────────────────────────
        # LINK — segmento IoMT
        # ──────────────────────────────────────────────────────────────
        self.addLink(r3, sw_iomt,
                     intfName1='r3-eth1',
                     addr1=mac_from_ip('10.0.30.1/24'),
                     params1={'ip': '10.0.30.1/24'})
        self.addLink(ris, sw_iomt)
        self.addLink(pacs, sw_iomt)
        self.addLink(modality, sw_iomt)
        self.addLink(attaccante, sw_iomt)


topos = {'hospitaltopo': (lambda: HospitalTopo())}
