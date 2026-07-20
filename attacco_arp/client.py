#!/usr/bin/env python3
"""
client.py — Client TCP minimale per test di connettività
============================================================
Controparte di echo_server.py. Si connette a un IP:porta e invia un
messaggio di test, poi stampa la risposta ricevuta.


Se la connessione va a buon fine, vedremo la risposta "ACK - connessione
ricevuta correttamente" stampata dal server. Se il firewall blocca il
traffico, il client resterà in attesa fino al timeout e poi stamperà un
errore (questo è il comportamento ATTESO per le connessioni che la
traccia vuole bloccate).
"""

import socket
import sys


def run(host, port, messaggio="TEST messaggio HL7 di prova", timeout=5):
    # Crea un oggetto socket per una connessione IPv4 (AF_INET) di tipo TCP (SOCK_STREAM)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Imposta un limite temporale massimo di attesa per le operazioni del socket.
    # Se il firewall esegue il DROP silenzioso del pacchetto, la connessione si interromperà dopo questi secondi.
    client_socket.settimeout(timeout)

    print('*** Tentativo di connessione a %s:%d (timeout %ds)...' % (host, port, timeout))

    try:
        # Avvia l'handshake TCP a tre vie per connettersi all'IP (host) e alla porta specificati
        client_socket.connect((host, port))
        print('*** Connessione stabilita! Invio messaggio...')

        # Converte il testo del messaggio in byte (codifica UTF-8) e lo invia al server
        client_socket.sendall(messaggio.encode('utf-8'))

        # Attende e riceve la risposta del server fino a un massimo di 4096 byte
        risposta = client_socket.recv(4096)
        print('*** Risposta dal server: %r' % risposta)
        
        # Se la transazione si completa con successo, significa che nessun firewall ha bloccato il transito
        print('*** ESITO: CONNESSIONE RIUSCITA (traffico permesso dal firewall)')

    # Gestisce il caso in cui scada il tempo limite impostato in precedenza
    except socket.timeout:
        print('*** ESITO: TIMEOUT — nessuna risposta entro %d secondi.' % timeout)
        print('    Probabile causa: il firewall sta scartando (DROP) il pacchetto.')

    # Gestisce il caso in cui il server di destinazione riceva il pacchetto ma non abbia servizi attivi
    except ConnectionRefusedError:
        print('*** ESITO: CONNESSIONE RIFIUTATA.')
        print('    Probabile causa: il pacchetto arriva a destinazione, ma')
        print('    nessun server è in ascolto su quella porta (avviate')
        print('    prima echo_server.py sul nodo di destinazione).')

    # Gestisce altri problemi generici legati al sistema operativo o alla tabella dei canali
    except OSError as e:
        print('*** ESITO: ERRORE DI RETE — %s' % e)
        print('    Probabile causa: routing mancante o interfaccia non raggiungibile.')

    # Questo blocco viene eseguito sempre prima di uscire dalla funzione
    finally:
        # Chiude in modo pulito e sicuro il socket del client rilasciando le risorse
        client_socket.close()


# Questo blocco si attiva solo se lo script viene lanciato direttamente (es. python3 client.py ...)
if __name__ == "__main__":
    # Verifica che siano stati passati almeno i due argomenti obbligatori: IP e Porta
    if len(sys.argv) < 3:
        print("Uso: python3 client.py <IP_destinazione> <porta> [messaggio]")
        sys.exit(1)

    # Estrae l'IP di destinazione dal primo parametro passato da riga di comando
    ip_dest = sys.argv[1]
    
    # Estrae la porta di destinazione dal secondo parametro e la converte in un numero intero
    porta_dest = int(sys.argv[2])
    
    # Se presente, usa il terzo parametro come messaggio personalizzato, altrimenti applica quello di default
    msg = sys.argv[3] if len(sys.argv) > 3 else "TEST messaggio HL7 di prova"

    # Esegue il flusso principale passando i parametri estratti
    run(ip_dest, porta_dest, msg)
