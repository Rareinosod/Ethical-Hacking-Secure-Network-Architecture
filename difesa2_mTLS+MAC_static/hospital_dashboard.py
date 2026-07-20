#!/usr/bin/env python3
"""
hospital_dashboard.py — Dashboard Unificata Rete Ospedaliera (lato clinico)
=============================================================================
App Flask con 3 tab: RIS · PACS · HIS.
Gira su Kali (fuori da Mininet), porta 8080.
Legge i file di log/JSON che i server HL7 scrivono in tempo reale.

Il tab Attacco NON è qui: C ha già la propria dashboard in mitm_hl7.py
(http://10.0.30.99:5000) che mostra i pacchetti intercettati/modificati.

Avvio: automatico da run.py (vedi patch_run.py.txt)
Browser: http://localhost:8080
"""

import json, logging as _logging, random, re, socket
import threading, time
from pathlib import Path
from flask import Flask, jsonify, request, Response
from hl7_parser import build_oru_r01, build_orm_o01_rp, wrap_mllp, DEFAULT_HL7_PORT
import os



BASE_DIR = Path(__file__).parent.resolve()

# ── Config ───────────────────────────────────────────────────────────────────

RIS_LOG  = BASE_DIR / 'ris_log.txt'
PACS_LOG = BASE_DIR / 'pacs_log.txt'
HIS_JSON = BASE_DIR / 'his_cartella_clinica.json'
WEB_PORT = 8080

PACS_HOST, PACS_PORT = "10.0.30.20", DEFAULT_HL7_PORT   # per invio manuale RIS
HIS_HOST,  HIS_PORT  = "10.0.20.10", 2577                # per invio manuale RIS
RIS_HOST,  RIS_PORT  = "10.0.30.10", 2576                # per invio ORM dal PACS

# ── Logging ──────────────────────────────────────────────────────────────────
_logging.getLogger("werkzeug").setLevel(_logging.ERROR)
logger = _logging.getLogger("DASHBOARD")
logger.setLevel(_logging.INFO)
_h = _logging.StreamHandler()
_h.setFormatter(_logging.Formatter("%(asctime)s [DASH] %(message)s", "%H:%M:%S"))
logger.addHandler(_h)

# ── Auto-send state (RIS) ─────────────────────────────────────────────────────
_auto_cfg  = {"attivo": False, "intervallo": 10}
_auto_stop = threading.Event()
_auto_thread = None

PAZIENTI = [("Rossi","Mario","19800315","M"),("Bianchi","Lucia","19750622","F"),
            ("Verdi","Giuseppe","19920110","M"),("Colombo","Anna","19650904","F")]
ESAMI = [
    ("TAC^TC Torace",
     "Polmoni con addensamento in base destra. Suggestivo per polmonite.",
     "Referto: polmonite lobare destra. Raccomandato follow-up a 30 giorni."),
    ("RX^Radiografia Torace","Campi polmonari liberi da addensamenti.",
     "Referto: quadro radiografico nella norma."),
    ("RM^Risonanza Magnetica Encefalo","Non si rilevano lesioni focali.",
     "Referto: esame nella norma, nessuna lesione di rilievo."),
    ("TAC^TC Addome","Fegato di dimensioni regolari, lieve steatosi.",
     "Referto: steatosi epatica lieve. Controllo ecografico a 6 mesi."),
]

# ── Log parsers ──────────────────────────────────────────────────────────────
def parse_ris_log():
    """Legge ris_log.txt e restituisce la lista dei referti inviati."""
    referti, current = {}, None
    try:
        with open(RIS_LOG, encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                m = re.search(r'(\d{2}:\d{2}:\d{2}) \[RIS\] NUOVO REFERTO.*Accession Number: (ACC\d+)', line)
                if m:
                    current = m.group(2)
                    referti[current] = {'acc': current, 'ts': m.group(1), 'paziente': '',
                                        'esame': '', 'conclusion_ris': '', 'orm_url': '', 'stato': 'IN CORSO'}
                if current and current in referti:
                    mp = re.search(r'\[RIS\] PID\|1\|\|[^|]+\|\|([^|]+)\|', line)
                    if mp: referti[current]['paziente'] = mp.group(1).replace('^', ' ')
                    mo = re.search(r'\[RIS\] OBR\|1\|[^|]+\|[^|]+\|([^|]+)\|', line)
                    if mo: referti[current]['esame'] = mo.group(1).replace('^', ' — ')
                    mc = re.search(r'\[RIS\] CONCLUSION inviato: (.+)$', line)
                    if mc: referti[current]['conclusion_ris'] = mc.group(1).strip()
                    if '[RIS] ORU^R01 inviato a PACS' in line:
                        referti[current]['stato'] = 'INVIATO'
                    mu = re.search(r'\[RIS\] URL immagini: (.+)$', line)
                    if mu: referti[current]['orm_url'] = mu.group(1).strip()
    except FileNotFoundError: pass
    except Exception as e: logger.error(f"parse_ris_log: {e}")
    return list(reversed(list(referti.values())))

def parse_pacs_log():
    """
    Legge pacs_log.txt e restituisce la lista dei referti ricevuti.
    Estrae tutti i campi necessari per costruire l'ORM^O01 RP manuale.
    Calcola attacco_rilevato confrontando CONCLUSION con quella del RIS.
    """
    referti, current, in_riepilogo = {}, None, False
    ris_by_acc = {r['acc']: r for r in parse_ris_log()}
    try:
        with open(PACS_LOG, encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if '[PACS] Nuova connessione' in line:
                    current, in_riepilogo = None, False

                # OBR in vista grezza spaziata → estrae ACC, ordine, esame
                m = re.search(r'(\d{2}:\d{2}:\d{2}) \[PACS\] OBR \| 1 \| (\w+) \| (ACC\d+) \| ([^\|]+)', line)
                if m:
                    current = m.group(3)
                    if current not in referti:
                        esame_raw = m.group(4).strip()
                        referti[current] = {
                            'acc': current, 'ts': m.group(1),
                            'ordine': m.group(2),
                            'esame_raw': esame_raw,               # es. "TAC^TC Torace" per costruire ORM
                            'esame': esame_raw.replace('^', ' — '),
                            'paz_id': '', 'cognome': '', 'nome': '',
                            'dob': '', 'sesso': '',
                            'radiologo': '', 'paziente': '',
                            'findings': '', 'conclusion_pacs': '',
                            'orm_inviato': False, 'orm_url': '',
                        }

                # PID in vista grezza spaziata → paziente, dob, sesso
                mp = re.search(r'\[PACS\] PID \| 1 \| [^|]* \| ([^|]+) \| [^|]* \| ([^|]+) \| [^|]* \| ([^|]+) \| ([^|]+)', line)
                if mp and current and current in referti:
                    paz_id   = mp.group(1).strip()
                    nome_hl7 = mp.group(2).strip()   # "Rossi^Mario"
                    dob      = mp.group(3).strip()
                    sesso    = mp.group(4).strip()
                    parts = nome_hl7.split('^')
                    referti[current].update({
                        'paz_id': paz_id.split('^^^')[0],
                        'cognome': parts[0], 'nome': parts[1] if len(parts) > 1 else '',
                        'dob': dob, 'sesso': sesso,
                        'paziente': nome_hl7.replace('^', ' '),
                    })

                # Radiologo: compare alla fine dell'OBR come "RAD00x"
                mr = re.search(r'\[PACS\] OBR.*\| (RAD\d+)\s*$', line)
                if mr and current and current in referti:
                    referti[current]['radiologo'] = mr.group(1).strip()

                # Riepilogo PACS
                if '[PACS] RIEPILOGO CAMPI' in line: in_riepilogo = True
                if in_riepilogo and '===' in line and 'RIEPILOGO' not in line:
                    in_riepilogo = False
                if in_riepilogo and current and current in referti:
                    mf = re.search(r'\[PACS\]\s+Findings\s*:\s*(.+)$', line)
                    if mf: referti[current]['findings'] = mf.group(1).strip()
                    mc = re.search(r'\[PACS\]\s+CONCLUSION\s*:\s*(.+)$', line)
                    if mc: referti[current]['conclusion_pacs'] = mc.group(1).strip()

                # ORM già inviato?
                if current and current in referti and '[PACS] ORM^O01 RP inviato a RIS' in line:
                    referti[current]['orm_inviato'] = True

                # URL immagini nell'ORM (OBX riga compatta)
                mu = re.search(r'\[PACS\] OBX\|1\|RP\|IMAGES\|\|(http://[^|]+)\|', line)
                if mu and current and current in referti:
                    referti[current]['orm_url'] = mu.group(1).strip()

    except FileNotFoundError: pass
    except Exception as e: logger.error(f"parse_pacs_log: {e}")

    # Confronto CONCLUSION RIS vs PACS → attacco_rilevato
    result = []
    for p in referti.values():
        r = ris_by_acc.get(p['acc'])
        p['conclusion_ris']    = r['conclusion_ris'] if r else ''
        p['attacco_rilevato']  = bool(
            r and p['conclusion_pacs'] and r['conclusion_ris']
            and p['conclusion_pacs'] != r['conclusion_ris'])
        p['url_default'] = p['orm_url'] or f"http://pacs.local/study/{p['acc']}"
        result.append(p)
    return list(reversed(result))

def parse_his_json():
    try:
        with open(HIS_JSON, encoding='utf-8') as f: return json.load(f)
    except: return {}

# ── HL7 send helpers ──────────────────────────────────────────────────────────
def _invia(framed, host, porta, dest):
    for t in range(1, 4):
        try:
            with socket.create_connection((host, porta), timeout=5) as s:
                s.sendall(framed)
            return True
        except Exception as e:
            if t < 3: time.sleep(2)
            else: logger.warning(f"Invio fallito → {dest}: {e}")
    return False

def _invia_oru(cognome, nome, dob, sesso, esame, findings, conclusion, radiologo):
    n   = random.randint(1000, 9999)
    acc = f"ACC{n}"
    hl7 = build_oru_r01(f"PAZ{n}", cognome, nome, dob, sesso, f"ORD{n}", acc,
                         esame, time.strftime("%Y%m%d%H%M%S"),
                         findings, conclusion, radiologo, f"MSG{n}")
    framed = wrap_mllp(hl7)
    ok_p = _invia(framed, PACS_HOST, PACS_PORT, "PACS")
    ok_h = _invia(framed, HIS_HOST,  HIS_PORT,  "HIS")
    logger.info(f"ORU manuale {acc} — PACS:{'OK' if ok_p else 'FAIL'} HIS:{'OK' if ok_h else 'FAIL'}")
    return acc, ok_p, ok_h

def _invia_orm(paz_id, cognome, nome, dob, sesso, ordine, acc, esame, radiologo, url):
    """Costruisce e invia ORM^O01 RP a RIS e HIS, esattamente come farebbe pacs_server.py."""
    orm = build_orm_o01_rp(
        paz_id, cognome, nome, dob, sesso,
        ordine, acc, esame,
        time.strftime("%Y%m%d%H%M%S"),
        url, radiologo
    )
    framed = wrap_mllp(orm)
    ok_r = _invia(framed, RIS_HOST, RIS_PORT, "RIS")
    ok_h = _invia(framed, HIS_HOST, HIS_PORT, "HIS")
    logger.info(f"ORM inviato {acc} URL={url} — RIS:{'OK' if ok_r else 'FAIL'} HIS:{'OK' if ok_h else 'FAIL'}")
    return ok_r, ok_h

def _loop_auto():
    logger.info("Auto-mode avviato")
    while not _auto_stop.wait(_auto_cfg["intervallo"]):
        c, n, db, s = random.choice(PAZIENTI)
        esame, findings, conclusion = random.choice(ESAMI)
        _invia_oru(c, n, db, s, esame, findings, conclusion,
                   random.choice(["RAD001","RAD002","RAD003"]))
    logger.info("Auto-mode fermato")

# ── Flask ─────────────────────────────────────────────────────────────────────
app = Flask(__name__)

@app.route('/')
def index(): return Response(HTML, mimetype='text/html')

@app.route('/api/all')
def api_all():
    ris  = parse_ris_log()
    pacs = parse_pacs_log()
    his  = parse_his_json()
    return jsonify(ris=ris, pacs=pacs, his=his,
                   auto=dict(_auto_cfg), ts=time.strftime("%H:%M:%S"))

@app.route('/api/invia_referto', methods=['POST'])
def api_invia_referto():
    d = request.get_json()
    acc, ok_p, ok_h = _invia_oru(
        d.get('cognome','Paziente'), d.get('nome',''),
        d.get('dob','19800101'), d.get('sesso','M'),
        d.get('esame','TAC^TC Torace'),
        d.get('findings',''), d.get('conclusion',''),
        d.get('radiologo','RAD001'))
    return jsonify(acc=acc, ok_pacs=ok_p, ok_his=ok_h)

@app.route('/api/invia_orm', methods=['POST'])
def api_invia_orm():
    """Invia l'ORM^O01 RP per un referto ricevuto dal PACS (Fase 8 manuale)."""
    d = request.get_json()
    acc     = d.get('acc', '')
    url     = d.get('url', f"http://pacs.local/study/{d.get('acc','')}")
    ok_r, ok_h = _invia_orm(
        d.get('paz_id',''),  d.get('cognome',''), d.get('nome',''),
        d.get('dob','19800101'), d.get('sesso','M'),
        d.get('ordine', f"ORD{acc.replace('ACC','')}"),
        acc, d.get('esame_raw','TAC^TC Torace'),
        d.get('radiologo','RAD001'), url)
    return jsonify(ok_ris=ok_r, ok_his=ok_h)

@app.route('/api/auto', methods=['POST'])
def api_auto():
    global _auto_thread
    d = request.get_json()
    attivo = d.get('attivo', False)
    _auto_cfg['intervallo'] = int(d.get('intervallo', 10))
    if attivo and not _auto_cfg['attivo']:
        _auto_cfg['attivo'] = True
        _auto_stop.clear()
        _auto_thread = threading.Thread(target=_loop_auto, daemon=True)
        _auto_thread.start()
    elif not attivo and _auto_cfg['attivo']:
        _auto_cfg['attivo'] = False
        _auto_stop.set()
    return jsonify(ok=True)

# ── HTML SPA ─────────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GruppoD — Rete Ospedaliera Sicura</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#060E1C;--sf:#0B1629;--sf2:#111E33;--bd:#1A2C47;--bd2:#243855;
--tx:#D8E8F8;--mt:#4E6785;--dm:#8BA4BF;
--ris:#00C2E0;--ris-d:rgba(0,194,224,.08);
--pacs:#8B7FEA;--pacs-d:rgba(139,127,234,.08);
--his:#00D97A;--his-d:rgba(0,217,122,.08);
--ok:#12F5A0;--ok-d:rgba(18,245,160,.1);
--warn:#F5A623;--warn-d:rgba(245,166,35,.1);
--err:#F5395C;--err-d:rgba(245,57,92,.1);
--sans:'Inter',system-ui,sans-serif;--mono:'JetBrains Mono',monospace;}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
body{font-family:var(--sans);background:var(--bg);color:var(--tx);min-height:100vh;font-size:13px;line-height:1.6;}
nav{position:sticky;top:0;z-index:100;background:rgba(6,14,28,.97);backdrop-filter:blur(16px);border-bottom:1px solid var(--bd);}
.nav-top{display:flex;align-items:center;gap:16px;padding:0 24px;height:52px;}
.brand{display:flex;align-items:center;gap:10px;margin-right:auto;}
.brand-name{font-size:15px;font-weight:700;}.brand-sub{font-size:10px;color:var(--mt);letter-spacing:.08em;text-transform:uppercase;}
.dot{width:7px;height:7px;border-radius:50%;background:var(--ok);animation:pulse 2.5s ease-in-out infinite;}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(18,245,160,.5);}50%{box-shadow:0 0 0 5px rgba(18,245,160,0);}}
.ts{font-family:var(--mono);font-size:11px;color:var(--mt);}
.tabs{display:flex;border-top:1px solid var(--bd);}
.tab{flex:1;display:flex;align-items:center;justify-content:center;gap:8px;padding:10px 0;
font-size:13px;font-weight:600;cursor:pointer;color:var(--mt);border-bottom:2px solid transparent;transition:all .2s;user-select:none;}
.tab:hover{color:var(--tx);}
.tab.ris.active{color:var(--ris);border-color:var(--ris);background:var(--ris-d);}
.tab.pacs.active{color:var(--pacs);border-color:var(--pacs);background:var(--pacs-d);}
.tab.his.active{color:var(--his);border-color:var(--his);background:var(--his-d);}
.cnt{font-family:var(--mono);font-size:10px;padding:1px 6px;border-radius:10px;background:var(--sf2);border:1px solid var(--bd);}
.section{display:none;max-width:1200px;margin:0 auto;padding:20px 24px;}
.section.active{display:flex;flex-direction:column;gap:16px;}
.card{background:var(--sf);border:1px solid var(--bd);border-radius:10px;overflow:hidden;}
.ch{display:flex;align-items:center;justify-content:space-between;padding:12px 18px;border-bottom:1px solid var(--bd);font-weight:600;font-size:13px;}
.ch-l{display:flex;align-items:center;gap:8px;}
.cols2{display:grid;grid-template-columns:370px 1fr;gap:16px;}
@media(max-width:900px){.cols2{grid-template-columns:1fr;}}
.fstack{display:flex;flex-direction:column;gap:11px;padding:18px;}
.field{display:flex;flex-direction:column;gap:5px;}
.r2{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
label{font-size:10px;font-weight:600;color:var(--mt);text-transform:uppercase;letter-spacing:.07em;}
input[type=text],input[type=date],input[type=number],input[type=url],select,textarea{
background:var(--sf2);border:1px solid var(--bd);border-radius:6px;color:var(--tx);
padding:8px 12px;font-size:13px;font-family:var(--sans);width:100%;transition:border-color .15s;}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--ris);box-shadow:0 0 0 3px var(--ris-d);}
.cf textarea{border-left:2px solid var(--ris);font-family:var(--mono);font-size:12px;background:rgba(0,194,224,.03);}
.cf label{color:var(--ris);}
.pacs-focus input[type=url]{border-left:2px solid var(--pacs);font-family:var(--mono);font-size:12px;}
.pacs-focus input[type=url]:focus{border-color:var(--pacs);box-shadow:0 0 0 3px var(--pacs-d);}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:8px 16px;
border-radius:7px;border:none;cursor:pointer;font-size:13px;font-weight:600;font-family:var(--sans);
transition:all .15s;white-space:nowrap;}
.btn-ris{background:var(--ris);color:#000;width:100%;margin-top:4px;padding:9px;}
.btn-ris:hover{filter:brightness(1.1);}.btn-ris:disabled{opacity:.5;cursor:not-allowed;}
.btn-pacs{background:var(--pacs);color:#fff;}
.btn-pacs:hover{filter:brightness(1.1);}.btn-pacs:disabled{opacity:.5;cursor:not-allowed;}
.btn-sent{background:var(--ok-d);color:var(--ok);border:1px solid rgba(18,245,160,.3);cursor:default;}
.trow{display:flex;align-items:center;gap:12px;padding:12px 18px;font-size:12px;color:var(--dm);}
.switch{position:relative;display:inline-block;width:40px;height:22px;}
.switch input{opacity:0;width:0;height:0;}
.sl{position:absolute;cursor:pointer;inset:0;background:var(--sf2);border:1px solid var(--bd);border-radius:22px;transition:.2s;}
.sl::before{content:'';position:absolute;width:16px;height:16px;left:2px;top:2px;background:var(--mt);border-radius:50%;transition:.2s;}
input:checked+.sl{background:var(--ris);border-color:var(--ris);}
input:checked+.sl::before{transform:translateX(18px);background:#000;}
.ib{display:flex;align-items:center;gap:8px;}.ib input{width:64px;text-align:center;}
.badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:20px;font-size:10px;font-weight:700;letter-spacing:.05em;font-family:var(--mono);}
.b-ok{background:var(--ok-d);color:var(--ok);}
.b-warn{background:var(--warn-d);color:var(--warn);}
.b-err{background:var(--err-d);color:var(--err);}
.b-ris{background:var(--ris-d);color:var(--ris);}
.b-pacs{background:var(--pacs-d);color:var(--pacs);}
.b-his{background:var(--his-d);color:var(--his);}
.cb-n{background:var(--sf2);color:var(--mt);font-family:var(--mono);font-size:11px;padding:1px 8px;border-radius:20px;border:1px solid var(--bd);}
.item{padding:12px 14px;border:1px solid var(--bd);border-radius:8px;transition:border-color .15s;animation:si .25s ease;}
.item+.item{margin-top:10px;}
.item:hover{border-color:var(--bd2);}
.ihead{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:6px;}
.acc{font-family:var(--mono);font-size:12px;font-weight:700;}
.ris-acc{color:var(--ris);}.pacs-acc{color:var(--pacs);}.his-acc{color:var(--his);}
.paz{font-weight:600;font-size:13px;}.meta{font-size:11px;color:var(--mt);font-family:var(--mono);}
.cbox{margin-top:8px;padding:8px 12px;border-radius:4px;font-size:11px;font-family:var(--mono);line-height:1.5;}
.cbox-ris{background:var(--ris-d);border-left:2px solid var(--ris);color:var(--dm);}
.cbox-pacs{background:var(--pacs-d);border-left:2px solid var(--pacs);color:var(--dm);}
.cbox-atk{background:var(--err-d);border-left:2px solid var(--err);color:var(--dm);}
.clabel{font-size:9px;font-weight:700;letter-spacing:.1em;display:block;margin-bottom:2px;}
.lris{color:var(--ris);}.lpacs{color:var(--pacs);}.lhis{color:var(--his);}.latk{color:var(--err);}
.compare{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:8px;}
@media(max-width:700px){.compare{grid-template-columns:1fr;}}
.orm-row{display:flex;align-items:flex-end;gap:10px;margin-top:12px;padding-top:12px;border-top:1px solid var(--bd);}
.orm-row .field{flex:1;}
.pcard{border:1px solid var(--bd);border-radius:10px;overflow:hidden;margin-bottom:12px;animation:si .3s ease;}
.phead{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;background:rgba(0,217,122,.04);border-bottom:1px solid var(--bd);}
.pname{font-size:15px;font-weight:700;}.pid{font-family:var(--mono);font-size:11px;color:var(--his);}
.pmeta{font-size:11px;color:var(--mt);font-family:var(--mono);margin-top:2px;}
.pbody{padding:14px 18px;display:flex;flex-direction:column;gap:10px;}
.exam{border:1px solid var(--bd);border-radius:8px;padding:12px 14px;background:var(--sf);}
.ehead{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;gap:8px;}
.etype{font-weight:600;font-size:13px;}.emeta{font-size:11px;color:var(--mt);font-family:var(--mono);margin-top:2px;}
.lscroll{max-height:560px;overflow-y:auto;padding:14px 18px;}
.lscroll::-webkit-scrollbar{width:4px;}
.lscroll::-webkit-scrollbar-thumb{background:var(--bd2);border-radius:2px;}
.empty{text-align:center;padding:50px 20px;color:var(--mt);}
.empty-i{font-size:32px;margin-bottom:10px;}
.atk-banner{display:none;align-items:center;gap:10px;padding:10px 16px;
background:var(--err-d);border:1px solid var(--err);border-radius:8px;font-size:12px;color:var(--err);font-weight:600;}
.atk-banner.show{display:flex;}
.auto-banner{display:none;align-items:center;gap:10px;padding:10px 18px;
background:rgba(0,194,224,.06);border:1px solid var(--ris);border-radius:8px;font-size:12px;color:var(--ris);font-weight:500;}
.auto-banner.show{display:flex;}
.spin{animation:spin 1s linear infinite;display:inline-block;}
@keyframes spin{to{transform:rotate(360deg);}}
.statusbar{display:flex;align-items:center;gap:20px;padding:8px 24px;background:var(--sf);
border-top:1px solid var(--bd);font-size:11px;font-family:var(--mono);color:var(--mt);flex-wrap:wrap;}
.sb-v{font-weight:600;color:var(--tx);}
#toast{position:fixed;bottom:60px;right:24px;padding:12px 18px;border-radius:8px;
font-size:13px;font-weight:500;display:none;z-index:999;animation:si .2s ease;}
#toast.ok{background:var(--ok);color:#000;}#toast.err{background:var(--err);color:#fff;}
#toast.warn{background:var(--warn);color:#000;}
@keyframes si{from{opacity:0;transform:translateY(-6px);}to{opacity:1;transform:translateY(0);}}
</style>
</head>
<body>

<nav>
  <div class="nav-top">
    <div class="brand">
      <span style="font-size:22px">🏥</span>
      <div><div class="brand-name">Rete Ospedaliera Sicura</div>
      <div class="brand-sub">GruppoD · Sistema Clinico</div></div>
    </div>
    <div class="dot"></div>
    <span class="ts" id="ts">--:--:--</span>
  </div>
  <div class="tabs">
    <div class="tab ris active" onclick="showTab('ris')">🔬 RIS <span class="cnt" id="tc-ris">0</span></div>
    <div class="tab pacs"       onclick="showTab('pacs')">🖼️ PACS <span class="cnt" id="tc-pacs">0</span></div>
    <div class="tab his"        onclick="showTab('his')">📂 HIS <span class="cnt" id="tc-his">0</span></div>
  </div>
</nav>

<!-- ═══ RIS ═══════════════════════════════════════════════════════════════ -->
<div id="sec-ris" class="section active">
  <div id="autoBanner" class="auto-banner"><span class="spin">⟳</span>
    Auto-mode attivo — un referto ogni <span id="bannerIntv">10</span>s
  </div>
  <div class="card">
    <div class="ch"><div class="ch-l">⚙️ Modalità di Invio</div>
      <div class="trow" style="padding:0;border:none;">
        <span>Manuale</span>
        <label class="switch"><input type="checkbox" id="autoTog" onchange="toggleAuto()"><span class="sl"></span></label>
        <span>Automatico</span>
        <div class="ib">
          <input type="number" id="intv" value="10" min="1" max="120">
          <span style="color:var(--mt)">s</span>
        </div>
      </div>
    </div>
  </div>
  <div class="cols2">
    <div class="card">
      <div class="ch"><div class="ch-l">📝 Nuovo Referto</div></div>
      <div class="fstack">
        <div class="r2">
          <div class="field"><label>Cognome</label><input type="text" id="cognome" placeholder="es. Rossi"></div>
          <div class="field"><label>Nome</label><input type="text" id="nome" placeholder="es. Mario"></div>
        </div>
        <div class="r2">
          <div class="field"><label>Data Nascita</label><input type="date" id="dob"></div>
          <div class="field"><label>Sesso</label>
            <select id="sesso"><option value="M">Maschile</option><option value="F">Femminile</option></select>
          </div>
        </div>
        <div class="field"><label>Esame</label>
          <select id="esame">
            <option value="TAC^TC Torace">TAC — TC Torace</option>
            <option value="RX^Radiografia Torace">RX — Radiografia Torace</option>
            <option value="RM^Risonanza Magnetica Encefalo">RM — Risonanza Magnetica Encefalo</option>
            <option value="TAC^TC Addome">TAC — TC Addome</option>
          </select>
        </div>
        <div class="field"><label>Findings</label>
          <textarea id="findings" placeholder="Descrizione immagini..."></textarea>
        </div>
        <div class="field cf">
          <label>⚠ CONCLUSION — campo target dell'attacco</label>
          <textarea id="conclusion" rows="3" placeholder="Diagnosi finale del radiologo..."></textarea>
        </div>
        <div class="field"><label>Radiologo</label>
          <select id="rad">
            <option value="RAD001">RAD001</option>
            <option value="RAD002">RAD002</option>
            <option value="RAD003">RAD003</option>
          </select>
        </div>
        <button class="btn btn-ris" id="sendBtn" onclick="inviaReferto()">📤 Invia a PACS + HIS</button>
      </div>
    </div>
    <div class="card">
      <div class="ch"><div class="ch-l">📋 Referti Inviati</div><span class="cb-n" id="cnt-ris">0</span></div>
      <div class="lscroll" id="list-ris">
        <div class="empty"><div class="empty-i">📋</div>Nessun referto — avvia ris_server.py o usa il form</div>
      </div>
    </div>
  </div>
</div>

<!-- ═══ PACS ════════════════════════════════════════════════════════════════ -->
<div id="sec-pacs" class="section">
  <div id="atk-banner" class="atk-banner">
    ⚠ ATTACCO RILEVATO — Il campo CONCLUSION è stato alterato in transito
  </div>
  <div class="card">
    <div class="ch">
      <div class="ch-l">🩻 Referti Ricevuti (Fase 7)</div>
      <div style="display:flex;align-items:center;gap:10px;">
        <span id="atk-count" style="display:none;font-size:11px;font-weight:600;color:var(--err);font-family:var(--mono);"></span>
        <span class="cb-n" id="cnt-pacs">0</span>
      </div>
    </div>
    <div class="lscroll" id="list-pacs">
      <div class="empty"><div class="empty-i">🩻</div>In attesa di referti dal RIS — porta 2575</div>
    </div>
  </div>
</div>

<!-- ═══ HIS ═════════════════════════════════════════════════════════════════ -->
<div id="sec-his" class="section">
  <div class="card">
    <div class="ch"><div class="ch-l">📂 Cartella Clinica Elettronica</div>
      <span class="cb-n" id="cnt-his">0 pazienti</span>
    </div>
    <div style="padding:18px;" id="cartella">
      <div class="empty"><div class="empty-i">🏥</div>Nessun paziente — porta HIS: 2577</div>
    </div>
  </div>
</div>

<div class="statusbar">
  <div style="display:flex;align-items:center;gap:6px;"><span class="dot" style="width:6px;height:6px;"></span>Live</div>
  <div>Aggiornamento: <span class="sb-v" id="sb-ts">--:--:--</span></div>
  <div>RIS inviati: <span class="sb-v" id="sb-ris">0</span></div>
  <div>PACS ricevuti: <span class="sb-v" id="sb-pacs">0</span></div>
  <div>Pazienti HIS: <span class="sb-v" id="sb-his">0</span></div>
</div>
<div id="toast"></div>

<script>
function showTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelector('.tab.' + name).classList.add('active');
  document.getElementById('sec-' + name).classList.add('active');
}

function toast(msg, type='ok') {
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = type; t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 3500);
}

// ── RIS ──────────────────────────────────────────────────────────────────────
async function inviaReferto() {
  const cognome = document.getElementById('cognome').value.trim();
  const conclusion = document.getElementById('conclusion').value.trim();
  if (!cognome || !conclusion) { toast('Cognome e Conclusione obbligatori', 'err'); return; }
  const dob = document.getElementById('dob').value.replace(/-/g,'') || '19800101';
  const btn = document.getElementById('sendBtn');
  btn.disabled = true; btn.textContent = '⏳ Invio…';
  try {
    const r = await fetch('/api/invia_referto', { method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ cognome, nome: document.getElementById('nome').value,
        dob, sesso: document.getElementById('sesso').value,
        esame: document.getElementById('esame').value,
        findings: document.getElementById('findings').value,
        conclusion, radiologo: document.getElementById('rad').value })});
    const d = await r.json();
    toast(d.ok_pacs && d.ok_his ? `✅ ${d.acc} inviato` : `⚠ ${d.acc} — invio parziale`, d.ok_pacs && d.ok_his ? 'ok':'warn');
  } catch(e) { toast('Errore di rete', 'err'); }
  btn.disabled = false; btn.textContent = '📤 Invia a PACS + HIS';
}

async function toggleAuto() {
  const attivo = document.getElementById('autoTog').checked;
  const intervallo = parseInt(document.getElementById('intv').value) || 10;
  await fetch('/api/auto', { method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({attivo, intervallo}) });
}

function renderRis(lista) {
  document.getElementById('cnt-ris').textContent = lista.length;
  document.getElementById('tc-ris').textContent = lista.length;
  document.getElementById('sb-ris').textContent = lista.length;
  const el = document.getElementById('list-ris');
  if (!lista.length) {
    el.innerHTML = '<div class="empty"><div class="empty-i">📋</div>Nessun referto — avvia ris_server.py o usa il form</div>';
    return;
  }
  el.innerHTML = lista.map(r => `
    <div class="item">
      <div class="ihead">
        <span class="acc ris-acc">${r.acc}</span>
        <span class="badge ${r.stato==='INVIATO'?'b-ok':'b-warn'}">${r.stato==='INVIATO'?'✅':'⏳'} ${r.stato}</span>
      </div>
      <div class="paz">${r.paziente||'—'}</div>
      <div class="meta">${r.esame||'—'} · ${r.ts}</div>
      <div class="cbox cbox-ris">
        <span class="clabel lris">CONCLUSION ORIGINALE (pre-attacco)</span>
        ${r.conclusion_ris||'—'}
      </div>
      ${r.orm_url ? `<div class="meta" style="margin-top:6px;">🖼️ ORM ricevuto: <span style="color:var(--dm)">${r.orm_url}</span></div>` : ''}
    </div>`).join('');
}

// ── PACS ─────────────────────────────────────────────────────────────────────
async function inviaOrm(acc) {
  const url     = document.getElementById('url_' + acc).value.trim();
  const btn     = document.getElementById('btn_' + acc);
  const pazId   = btn.dataset.paz_id;
  const cognome = btn.dataset.cognome;
  const nome    = btn.dataset.nome;
  const dob     = btn.dataset.dob;
  const sesso   = btn.dataset.sesso;
  const ordine  = btn.dataset.ordine;
  const esameR  = btn.dataset.esame_raw;
  const rad     = btn.dataset.radiologo;

  btn.disabled = true; btn.textContent = '⏳ Invio…';
  try {
    const r = await fetch('/api/invia_orm', { method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ acc, url, paz_id:pazId, cognome, nome,
        dob, sesso, ordine, esame_raw:esameR, radiologo:rad }) });
    const d = await r.json();
    if (d.ok_ris || d.ok_his) {
      toast(`✅ ORM inviato per ${acc} — RIS:${d.ok_ris?'✓':'✗'} HIS:${d.ok_his?'✓':'✗'}`, 'ok');
      btn.textContent = '✅ ORM Inviato'; btn.className = 'btn btn-sent';
    } else {
      toast(`❌ Invio ORM fallito per ${acc}`, 'err');
      btn.disabled = false; btn.textContent = '📤 Invia ORM';
    }
  } catch(e) { toast('Errore di rete', 'err'); btn.disabled=false; btn.textContent='📤 Invia ORM'; }
}

function renderPacs(lista) {
  document.getElementById('cnt-pacs').textContent = lista.length;
  document.getElementById('tc-pacs').textContent = lista.length;
  document.getElementById('sb-pacs').textContent = lista.length;
  const attacchi = lista.filter(p => p.attacco_rilevato).length;
  const banner = document.getElementById('atk-banner');
  const count  = document.getElementById('atk-count');
  if (attacchi > 0) {
    banner.classList.add('show');
    count.style.display = 'inline';
    count.textContent = `⚠ ${attacchi} MODIFICATO${attacchi>1?'I':''}`;
  } else { banner.classList.remove('show'); count.style.display='none'; }
  const el = document.getElementById('list-pacs');
  if (!lista.length) {
    el.innerHTML = '<div class="empty"><div class="empty-i">🩻</div>In attesa di referti dal RIS — porta 2575</div>';
    return;
  }
  el.innerHTML = lista.map(p => {
    const atkStyle = p.attacco_rilevato ? 'border-color:var(--err);background:rgba(245,57,92,.02)' : '';
    const ormRow = p.orm_inviato
      ? `<div class="meta" style="margin-top:10px;padding-top:10px;border-top:1px solid var(--bd);">
           ✅ ORM inviato · 🖼️ <span style="color:var(--dm)">${p.orm_url}</span>
         </div>`
      : `<div class="orm-row">
           <div class="field pacs-focus">
             <label>📁 URL Archivio Immagini Radiologiche (DICOM)</label>
             <input type="url" id="url_${p.acc}" value="${p.url_default}" placeholder="http://pacs.local/study/...">
           </div>
           <button class="btn btn-pacs" id="btn_${p.acc}" onclick="inviaOrm('${p.acc}')"
             data-paz_id="${p.paz_id}" data-cognome="${p.cognome}" data-nome="${p.nome}"
             data-dob="${p.dob}" data-sesso="${p.sesso}" data-ordine="${p.ordine}"
             data-esame_raw="${p.esame_raw}" data-radiologo="${p.radiologo}">
             📤 Invia ORM a RIS + HIS
           </button>
         </div>`;
    return `<div class="item" style="${atkStyle}">
      <div class="ihead">
        <div><span class="acc pacs-acc">${p.acc}</span>
          ${p.attacco_rilevato ? '<span class="badge b-err" style="margin-left:8px;">⚠ CONCLUSION ALTERATA</span>' : ''}
        </div>
        <span class="badge b-pacs">RICEVUTO · ${p.ts}</span>
      </div>
      <div class="paz">${p.paziente||'—'}</div>
      <div class="meta">${p.esame||'—'}</div>
      <div class="compare">
        <div class="cbox cbox-ris">
          <span class="clabel lris">ORIGINALE DAL RIS</span>
          ${p.conclusion_ris || '<em style="opacity:.5">non disponibile</em>'}
        </div>
        <div class="cbox ${p.attacco_rilevato ? 'cbox-atk' : 'cbox-pacs'}">
          <span class="clabel ${p.attacco_rilevato ? 'latk' : 'lpacs'}">
            RICEVUTO DAL PACS ${p.attacco_rilevato ? '⚠ ALTERATO' : ''}
          </span>
          ${p.conclusion_pacs||'—'}
        </div>
      </div>
      ${ormRow}
    </div>`;
  }).join('');
}

// ── HIS ──────────────────────────────────────────────────────────────────────
function renderHis(cartella) {
  const pazienti = Object.entries(cartella);
  document.getElementById('cnt-his').textContent = pazienti.length + ' pazient' + (pazienti.length===1?'e':'i');
  document.getElementById('tc-his').textContent = pazienti.length;
  document.getElementById('sb-his').textContent = pazienti.length;
  const el = document.getElementById('cartella');
  if (!pazienti.length) {
    el.innerHTML = '<div class="empty"><div class="empty-i">🏥</div>Nessun paziente — porta HIS: 2577</div>';
    return;
  }
  el.innerHTML = [...pazienti].reverse().map(([pid, p]) => {
    const esami = Object.entries(p.esami||{});
    const dob   = (p.dob||'').replace(/(\d{4})(\d{2})(\d{2})/,'$3/$2/$1');
    const nome  = (p.nome||'').replace('^',' ');
    return `<div class="pcard">
      <div class="phead">
        <div><div class="pname">${nome}</div><div class="pmeta">${dob} · ${p.sesso==='M'?'♂ M':'♀ F'}</div></div>
        <div style="text-align:right;"><div class="pid">${pid}</div>
          <div style="font-size:11px;color:var(--mt);margin-top:2px">${esami.length} esam${esami.length===1?'e':'i'}</div>
        </div>
      </div>
      <div class="pbody">${esami.length ? [...esami].reverse().map(([acc,e]) => `
        <div class="exam">
          <div class="ehead">
            <div><div class="etype">${(e.esame||'').replace('^',' — ')}</div>
            <div class="emeta">${acc} · ${e.radiologo||''} · ${e.ts_referto||''}</div></div>
            <span class="badge ${e.immagini?'b-ok':'b-warn'}">${e.immagini?'✅ Immagini ok':'⏳ In attesa'}</span>
          </div>
          <div class="cbox cbox-ris" style="margin-bottom:0;">
            <span class="clabel lris">CONCLUSION (arrivato direttamente dal RIS)</span>${e.conclusion||'—'}
          </div>
          ${e.url_immagini?`<div class="meta" style="margin-top:6px;">🖼️ ${e.url_immagini}</div>`:''}
        </div>`).join('') :
        '<div style="color:var(--mt);text-align:center;padding:12px;font-size:12px;">Nessun esame</div>'}
      </div>
    </div>`;
  }).join('');
}

// ── Polling ──────────────────────────────────────────────────────────────────
async function fetchAll() {
  try {
    const r = await fetch('/api/all');
    const d = await r.json();
    document.getElementById('ts').textContent    = d.ts;
    document.getElementById('sb-ts').textContent = d.ts;
    // Auto-mode UI
    document.getElementById('autoTog').checked = d.auto.attivo;
    document.getElementById('intv').value      = d.auto.intervallo;
    const ab = document.getElementById('autoBanner');
    if (d.auto.attivo) { ab.classList.add('show'); document.getElementById('bannerIntv').textContent = d.auto.intervallo; }
    else ab.classList.remove('show');
    renderRis(d.ris);
    renderPacs(d.pacs);
    renderHis(d.his);
  } catch(e) {}
}

setInterval(fetchAll, 2000);
fetchAll();
</script>
</body>
</html>"""

def main():
    logger.info(f"Dashboard avviata → http://localhost:{WEB_PORT}")
    logger.info(f"Log directory: {BASE_DIR}")
    app.run(host="0.0.0.0", port=WEB_PORT, threaded=True, use_reloader=False, debug=False)

if __name__ == '__main__':
    main()
