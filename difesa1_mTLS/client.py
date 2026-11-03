#!/usr/bin/env python3
"""
client.py — Client TCP minimale per test di connettività
============================================================
Controparte di echo_server.py. Si connette a un IP:porta e invia un
messaggio di test, poi stampa la risposta ricevuta. Stesso schema visto a
lezione per il test client/server HL7 (un host manda, l'altro riceve e
risponde) — qui semplificato per validare solo la RAGGIUNGIBILITÀ
(firewall + routing), non il contenuto applicativo HL7 vero e proprio.

USO (dalla CLI di Mininet):
    his_srv python3 client.py 10.0.30.10 2575
    pc_admin python3 client.py 10.0.30.10 2575

Se la connessione va a buon fine, vedrete la risposta "ACK - connessione
ricevuta correttamente" stampata dal server. Se il firewall blocca il
traffico, il client resterà in attesa fino al timeout e poi stamperà un
errore (questo è il comportamento ATTESO per le connessioni che la
traccia vuole bloccate).
"""

import socket
import sys


def run(host, port, messaggio="TEST messaggio HL7 di prova", timeout=5):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(timeout)

    print('*** Tentativo di connessione a %s:%d (timeout %ds)...' % (host, port, timeout))

    try:
        client_socket.connect((host, port))
        print('*** Connessione stabilita! Invio messaggio...')

        client_socket.sendall(messaggio.encode('utf-8'))

        risposta = client_socket.recv(4096)
        print('*** Risposta dal server: %r' % risposta)
        print('*** ESITO: CONNESSIONE RIUSCITA (traffico permesso dal firewall)')

    except socket.timeout:
        print('*** ESITO: TIMEOUT — nessuna risposta entro %d secondi.' % timeout)
        print('    Probabile causa: il firewall sta scartando (DROP) il pacchetto.')

    except ConnectionRefusedError:
        print('*** ESITO: CONNESSIONE RIFIUTATA.')
        print('    Probabile causa: il pacchetto arriva a destinazione, ma')
        print('    nessun server è in ascolto su quella porta (avviate')
        print('    prima echo_server.py sul nodo di destinazione).')

    except OSError as e:
        print('*** ESITO: ERRORE DI RETE — %s' % e)
        print('    Probabile causa: routing mancante o interfaccia non raggiungibile.')

    finally:
        client_socket.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python3 client.py <IP_destinazione> <porta> [messaggio]")
        sys.exit(1)

    ip_dest = sys.argv[1]
    porta_dest = int(sys.argv[2])
    msg = sys.argv[3] if len(sys.argv) > 3 else "TEST messaggio HL7 di prova"

    run(ip_dest, porta_dest, msg)
