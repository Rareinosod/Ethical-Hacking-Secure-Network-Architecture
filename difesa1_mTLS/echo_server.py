#!/usr/bin/env python3
"""
echo_server.py — Server TCP minimale per test di connettività
================================================================
Server "segnaposto" per RIS, PACS e HIS, usato SOLO per verificare che le
regole iptables di R3 funzionino correttamente (HIS <-> RIS/PACS sulla
porta HL7), prima che il Sottogruppo B integri i server HL7 reali
(ris_server.py, pacs_server.py, his_server.py).

A differenza di server.py (HTTP), questo è un semplice server TCP grezzo
("echo"): accetta una connessione, stampa cosa riceve, e risponde con un
messaggio di conferma. Non implementa HL7/MLLP — serve solo a dimostrare
che il PACCHETTO ARRIVA, non a validare il contenuto applicativo (quello è
compito dei server reali del Sottogruppo B).

USO (dalla CLI di Mininet):
    h_ris  python3 echo_server.py 2575
    h_pacs python3 echo_server.py 2575
    his_srv python3 echo_server.py 2575

Se non specificate la porta, usa di default 2575 (porta HL7 RIS<->PACS
concordata nel contratto tecnico cross-gruppo).

Per testare una connessione dal lato client, da un altro host:
    his_srv bash -c "echo 'TEST HL7' | nc 10.0.30.10 2575"
"""

import socket
import sys


def run(port=2575):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', port))
    server_socket.listen(5)

    print('*** Echo server in ascolto sulla porta %d (Ctrl+C per fermare)' % port)

    try:
        while True:
            conn, addr = server_socket.accept()
            print('*** Connessione ricevuta da %s:%d' % addr)

            data = conn.recv(4096)
            if data:
                print('*** Dati ricevuti (%d byte): %r' % (len(data), data[:200]))

            risposta = b'ACK - connessione ricevuta correttamente\n'
            conn.sendall(risposta)
            conn.close()
    except KeyboardInterrupt:
        print('\n*** Arresto del server')
    finally:
        server_socket.close()


if __name__ == "__main__":
    porta = int(sys.argv[1]) if len(sys.argv) == 2 else 2575
    run(port=porta)
