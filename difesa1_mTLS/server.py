#!/usr/bin/env python3
"""
server.py — Web Server di test per il segmento DMZ
=====================================================
Server HTTP minimale, identico nella logica a quello usato nelle
esercitazioni (switch1/router1/router2): risponde "Hello world!" a ogni
richiesta GET. Serve per verificare la connettività end-to-end e le regole
del firewall (R1: Internet->WebServer permesso; R2: Enterprise->WebServer
NON permesso dalla traccia).

USO (dentro il terminale dell'host web_srv, nella CLI di Mininet):
    web_srv python3 server.py

Di default ascolta sulla porta 80 (come richiesto dalla traccia per il
traffico HTTP). Per HTTPS (443) serve un setup diverso (certificati TLS),
che esula dal semplice test di connettività — qui testiamo solo HTTP.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer


class Server(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        message = "Hello world! (Web Server - DMZ)"
        self.wfile.write(bytes(message, "utf8"))

    def log_message(self, format, *args):
        # Sopprime il log di default per non intasare il terminale
        return


def run(server_class=HTTPServer, handler_class=Server, port=80):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print('*** Web Server DMZ in ascolto sulla porta %d...' % port)
    httpd.serve_forever()


if __name__ == "__main__":
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
