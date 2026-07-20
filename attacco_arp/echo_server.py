#!/usr/bin/env python3
"""
echo_server.py — Server TCP minimale per test di connettività
================================================================
Server usato SOLO per verificare che le regole iptables di R3 
funzionino correttamente (HIS <-> RIS/PACS sulla
porta HL7), prima che si integrino i server HL7 reali
(ris_server.py, pacs_server.py, his_server.py).

A differenza di server.py (HTTP), questo è un semplice server TCP grezzo
("echo"): accetta una connessione, stampa cosa riceve, e risponde con un
messaggio di conferma. Non implementa HL7/MLLP — serve solo a dimostrare
che il PACCHETTO ARRIVA, non a validare il contenuto applicativo (quello è
compito dei server reali).

"""

import socket
import sys


def run(port=2575):
    # Crea un oggetto socket per una connessione di rete IPv4 (AF_INET) di tipo TCP (SOCK_STREAM)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Imposta un'opzione a livello di socket per riutilizzare immediatamente l'indirizzo/porta.
    # Questo evita l'errore "Address already in use" se riavviamo il server rapidamente.
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Associa (bind) il server a tutte le interfacce di rete disponibili ('') e alla porta scelta
    server_socket.bind(('', port))
    
    # Mette il socket in modalità ascolto. Il parametro "5" indica quante connessioni 
    # in coda il sistema operativo può accodare prima di rifiutarle.
    server_socket.listen(5)

    print('*** Echo server in ascolto sulla porta %d (Ctrl+C per fermare)' % port)

    try:
        # Avvia un ciclo infinito: il server girerà per sempre in attesa di richieste
        while True:
            # Il server si "mette in pausa" (blocca) finché non riceve una connessione.
            # Quando arriva, restituisce un nuovo socket dedicato al client (conn) e i suoi dati (addr)
            conn, addr = server_socket.accept()
            print('*** Connessione ricevuta da %s:%d' % addr)

            # Legge fino a 4096 byte di dati in ingresso inviati dal client
            data = conn.recv(4096)
            if data:
                # Se sono arrivati dei dati, li stampa a schermo (limitandosi ai primi 200 caratteri)
                print('*** Dati ricevuti (%d byte): %r' % (len(data), data[:200]))

            # Prepara il messaggio di risposta. La 'b' davanti alla stringa indica che sono byte grezzi
            risposta = b'ACK - connessione ricevuta correttamente\n'
            
            # Invia l'intero messaggio di conferma (ACK) indietro al client
            conn.sendall(risposta)
            
            # Chiude la connessione con il client attuale, pronto per ricominciare il ciclo col prossimo
            conn.close()
            
    # Cattura l'evento in cui l'utente preme la combinazione Ctrl+C nel terminale
    except KeyboardInterrupt:
        print('\n*** Arresto del server')
        
    # Il blocco finally viene eseguito SEMPRE, sia in caso di errore che di chiusura manuale
    finally:
        # Chiude in modo sicuro il socket principale mettendosi in regola con il sistema operativo
        server_socket.close()

# Questo blocco viene eseguito solo se lo script viene lanciato direttamente (non importato come modulo)
if __name__ == "__main__":
    # Se viene passato un parametro da riga di comando,
    # converte quell'argomento in intero e lo usa come porta. Altrimenti usa 2575 di default (la porta HL7).
    porta = int(sys.argv[1]) if len(sys.argv) == 2 else 2575
    
    # Avvia la funzione principale del server passando la porta decisa al passo precedente
    run(port=porta)