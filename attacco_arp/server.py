#!/usr/bin/env python3
"""
server.py — Web Server di test per il segmento DMZ
=====================================================
USO (dentro il terminale dell'host web_srv, nella CLI di Mininet):
    web_srv python3 server.py

Di default ascolta sulla porta 80. Per HTTPS (443) serve un setup diverso (certificati TLS),
che esula dal semplice test di connettività.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer


class Server(BaseHTTPRequestHandler):

    # Metodo richiamato automaticamente quando il server riceve una richiesta HTTP GET
    def do_GET(self):
        # 1. Invia il codice di stato HTTP (200 = OK)
        self.send_response(200)
        
        # 2. Specifica che il payload in arrivo è testo HTML e chiude gli header
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # 3. Prepara il messaggio. I dati viaggiano sul socket come byte, 
        # quindi è necessaria la conversione della stringa con codifica UTF-8
        message = "Hello world! (Web Server - DMZ)"
        self.wfile.write(bytes(message, "utf8"))

    def log_message(self, format, *args):
        # Sopprime il log di default per non intasare il terminale
        return


def run(server_class=HTTPServer, handler_class=Server, port=80):
    # La stringa vuota '' in server_address equivale a 0.0.0.0
    # Consente al server di ascoltare su tutte le interfacce di rete del nodo
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print('*** Web Server DMZ in ascolto sulla porta %d...' % port)
    
    # Mantiene in esecuzione il servizio bloccando il thread principale
    httpd.serve_forever()


if __name__ == "__main__":
    from sys import argv

    # Se viene passato un argomento da terminale (es. python3 server.py 8080), 
    # lo utilizza come porta; altrimenti usa la 80 di default.
    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
