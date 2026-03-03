"""
Agent Comptable IA - v4.0 SECURE
Traitement automatique de tickets de frais → écritures comptables Sage
Multi-provider : Claude → OpenAI → Ollama (fallback)
Sécurité : Auth, CSRF, Zero Data Retention, Anti-injection, Headers
"""

import os
import io
import json
import base64
import re
import time
import email
import imaplib
import smtplib
import threading
import secrets
import hashlib
import hmac
from functools import wraps
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
from pathlib import Path

import requests
from flask import (
    Flask, request, jsonify, render_template, send_file,
    session, redirect, url_for, abort, make_response,
    after_this_request
)
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import red, black
from reportlab.lib.pagesizes import A4
import fitz  # PyMuPDF

app = Flask(__name__)


# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

# --- Sécurité ---
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FORCE_HTTPS', 'false').lower() == 'true'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# --- Identifiants login (via env, JAMAIS en dur) ---
APP_USERNAME = os.environ.get('APP_USERNAME', 'admin')
APP_PASSWORD_HASH = os.environ.get('APP_PASSWORD_HASH', '')
APP_PASSWORD_PLAIN = os.environ.get('APP_PASSWORD', 'changeme')

# --- API Keys ---
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
OLLAMA_URL = os.environ.get('OLLAMA_URL', 'http://localhost:11434')
OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'qwen3-vl')

# --- Retry & Rate Limiting ---
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2
RATE_LIMIT_DELAY = 1.5
RATE_LIMIT_429_WAIT = 30

# --- Brute-force protection ---
LOGIN_ATTEMPTS = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # 5 minutes

# --- Dossiers (temporaires, nettoyés après usage) ---
OUTPUT_FOLDER = Path('outputs')
OUTPUT_FOLDER.mkdir(exist_ok=True)

# --- Auto-delete : supprimer les fichiers de plus de X minutes ---
FILE_RETENTION_MINUTES = int(os.environ.get('FILE_RETENTION_MINUTES', '10'))

# --- Email (optionnel) ---
EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS', '')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')
IMAP_SERVER = 'imap.gmail.com'
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 465
CHECK_INTERVAL = 30


# ═══════════════════════════════════════════════════════════════════
# SÉCURITÉ : HELPERS
# ═══════════════════════════════════════════════════════════════════

def hash_password(password):
    """Hash un mot de passe avec SHA-256 + salt"""
    salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"{salt}:{h}"


def verify_password(password, stored_hash):
    """Vérifie un mot de passe contre son hash"""
    if ':' not in stored_hash:
        return False
    salt, h = stored_hash.split(':', 1)
    return hmac.compare_digest(
        hashlib.sha256(f"{salt}{password}".encode()).hexdigest(),
        h
    )


def check_password(password):
    """Vérifie le mot de passe (hash ou plain selon config)"""
    if APP_PASSWORD_HASH:
        return verify_password(password, APP_PASSWORD_HASH)
    return hmac.compare_digest(password, APP_PASSWORD_PLAIN)


def is_locked_out(ip):
    """Vérifie si une IP est bloquée pour trop de tentatives"""
    if ip in LOGIN_ATTEMPTS:
        attempts, lockout_time = LOGIN_ATTEMPTS[ip]
        if lockout_time and datetime.now() < lockout_time:
            return True
        if lockout_time and datetime.now() >= lockout_time:
            del LOGIN_ATTEMPTS[ip]
            return False
    return False


def record_failed_attempt(ip):
    """Enregistre une tentative de login échouée"""
    if ip not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip] = [0, None]
    LOGIN_ATTEMPTS[ip][0] += 1
    if LOGIN_ATTEMPTS[ip][0] >= MAX_LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip][1] = datetime.now() + timedelta(seconds=LOCKOUT_DURATION)


def clear_attempts(ip):
    """Reset les tentatives après un login réussi"""
    if ip in LOGIN_ATTEMPTS:
        del LOGIN_ATTEMPTS[ip]


def login_required(f):
    """Décorateur pour protéger les routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Non authentifie'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def generate_csrf_token():
    """Génère un token CSRF"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def validate_csrf(token):
    """Valide le token CSRF"""
    return hmac.compare_digest(
        token or '',
        session.get('csrf_token', '')
    )


def sanitize_filename(filename):
    """Nettoie un nom de fichier contre les injections path traversal"""
    filename = os.path.basename(filename)
    filename = re.sub(r'[^\w\s\-\.]', '', filename)
    filename = filename.strip('. ')
    if not filename:
        filename = 'document.pdf'
    return filename


def cleanup_old_files():
    """Supprime les fichiers de sortie de plus de FILE_RETENTION_MINUTES"""
    try:
        cutoff = datetime.now() - timedelta(minutes=FILE_RETENTION_MINUTES)
        for f in OUTPUT_FOLDER.iterdir():
            if f.is_file():
                mtime = datetime.fromtimestamp(f.stat().st_mtime)
                if mtime < cutoff:
                    f.unlink()
                    print(f"  [Cleanup] Supprime {f.name}")
    except Exception as e:
        print(f"  [Cleanup] Erreur: {e}")


def schedule_cleanup():
    """Lance le nettoyage automatique toutes les 5 minutes"""
    while True:
        time.sleep(300)
        cleanup_old_files()


# ═══════════════════════════════════════════════════════════════════
# SÉCURITÉ : MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════

@app.before_request
def security_checks():
    """Vérifications de sécurité avant chaque requête"""
    # CSRF sur les POST (sauf login et API avec session)
    if request.method == 'POST' and request.path != '/login':
        if session.get('authenticated'):
            token = (request.form.get('csrf_token') or
                     request.headers.get('X-CSRF-Token') or
                     '')
            if not validate_csrf(token):
                abort(403)


@app.after_request
def security_headers(response):
    """Headers de sécurité sur toutes les réponses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    # Pas de cache sur les fichiers sensibles
    if request.path.startswith('/api/download'):
        response.headers['Cache-Control'] = 'no-store'
    return response


# ═══════════════════════════════════════════════════════════════════
# PROMPT COMPTABLE
# ═══════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """Tu es un expert-comptable français spécialisé en Plan Comptable Général (PCG), fiscalité TVA et préparation de fichiers d'import pour Sage. Tu traites des tickets de frais professionnels.

RÈGLES IMPÉRATIVES :
1. 1 ticket = 1 écriture (jamais de regroupement)
2. Équilibre obligatoire : total Débit = total Crédit
3. Comptes généraux sur 8 caractères (ex: 6251 → 62510000)
4. Journal : toujours FCB
5. Compte crédit : toujours 51200000 (banque CB)
6. Références séquentielles : T1, T2, T3...
7. Dates au format JJ/MM/AAAA - utilise la date figurant sur le document
8. Montants avec 2 décimales
9. En cas de doute : signaler plutôt que deviner

IMPORTANT : Une page peut contenir PLUSIEURS tickets. Analyse CHAQUE ticket séparément.

RÈGLES TVA :
- Péage, autoroute : TVA 20% → 100% déductible
- Carburant véhicule tourisme diesel/essence : TVA 80% déductible. Les 20% non déductibles sont réintégrés dans la charge (charge = HT + TVA×0.20)
- Repas, restaurant : TVA NON déductible (tout en TTC dans la charge, pas de ligne TVA)
- Hébergement, hôtel : TVA NON déductible (tout en TTC dans la charge)
- Fournitures, achats divers : TVA 20% → 100% déductible
- Parking : TVA 20% → 100% déductible

COMPTES DE CHARGES (8 caractères) :
- 62510000 : Voyages et déplacements (train, avion, péage, taxi)
- 62520000 : Frais de carburant
- 62560000 : Missions - repas
- 62560100 : Missions - hébergement
- 60680000 : Achats divers (fournitures, matériel, téléphone)
- 62780000 : Frais divers (parking, timbres, autres)
- 44566000 : TVA déductible sur ABS

MÉTHODE DE CALCUL OBLIGATOIRE :
1. Identifie le montant TTC total payé
2. Identifie le montant TVA
3. Calcule HT = TTC - TVA
4. Si TVA déductible 100% : débit charge = HT, débit TVA = montant TVA, crédit banque = TTC
5. Si TVA déductible 80% (carburant tourisme) : débit charge = HT + TVA×0.20, débit TVA = TVA×0.80, crédit banque = TTC
6. Si TVA non déductible (repas, hôtel) : débit charge = TTC, crédit banque = TTC (2 lignes seulement)
7. VÉRIFIE TOUJOURS : somme débits = somme crédits = TTC

CONTRÔLE : Vérifie que HT + TVA = TTC (tolérance ±0.01€)

exploitable=false UNIQUEMENT si :
- Ticket illisible ou scan de mauvaise qualité
- Ticket CB sans aucun détail (simple preuve de paiement)
- Informations essentielles manquantes (montant, date)
Ne juge JAMAIS la nature professionnelle ou non de la dépense.

Réponds UNIQUEMENT avec un JSON valide sans backticks ni texte autour :
{"exploitable": true, "raison_non_exploitable": "", "ecritures": [{"date": "JJ/MM/AAAA", "reference": "T1", "journal": "FCB", "compte": "XXXXXXXX", "libelle": "Fournisseur - Nature de la dépense", "debit": 0.00, "credit": 0.00}]}"""


# ═══════════════════════════════════════════════════════════════════
# UTILITAIRES PDF
# ═══════════════════════════════════════════════════════════════════

def extract_text_from_pdf(pdf_bytes):
    """Extrait le texte d'un PDF avec PyMuPDF"""
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        text = ""
        for page in doc:
            text += page.get_text()
        doc.close()
        return text.strip()
    except Exception:
        return ""


def split_pdf_pages(pdf_bytes, filename):
    """Découpe un PDF en pages individuelles"""
    reader = PdfReader(io.BytesIO(pdf_bytes))
    pages = []
    for i, page in enumerate(reader.pages):
        writer = PdfWriter()
        writer.add_page(page)
        output = io.BytesIO()
        writer.write(output)
        output.seek(0)
        page_name = f"{Path(filename).stem}_page{i+1}.pdf"
        pages.append({
            'filename': page_name,
            'bytes': output.read(),
            'original_filename': filename
        })
    return pages


def stamp_pdf_with_s(pdf_bytes):
    """Ajoute un S rouge sur le PDF"""
    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter()
    for page in reader.pages:
        packet = io.BytesIO()
        w = float(page.mediabox.width)
        h = float(page.mediabox.height)
        c = canvas.Canvas(packet, pagesize=(w, h))
        c.setFont("Helvetica-Bold", 60)
        c.setFillColor(red)
        c.setFillAlpha(0.7)
        c.drawString(w - 70, h - 70, "S")
        c.save()
        packet.seek(0)
        overlay = PdfReader(packet)
        page.merge_page(overlay.pages[0])
        writer.add_page(page)
    output = io.BytesIO()
    writer.write(output)
    output.seek(0)
    return output.read()


def merge_pdfs(pdf_list):
    """Fusionne plusieurs PDFs en un seul"""
    writer = PdfWriter()
    for pdf_bytes in pdf_list:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        for page in reader.pages:
            writer.add_page(page)
    output = io.BytesIO()
    writer.write(output)
    output.seek(0)
    return output.read()


# ═══════════════════════════════════════════════════════════════════
# PROVIDERS IA
# ═══════════════════════════════════════════════════════════════════

def call_anthropic(user_content):
    """Appel Claude API"""
    if not ANTHROPIC_API_KEY:
        raise Exception("Anthropic: cle API non configuree")

    response = requests.post(
        'https://api.anthropic.com/v1/messages',
        headers={
            'Content-Type': 'application/json',
            'x-api-key': ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01'
        },
        json={
            'model': 'claude-sonnet-4-20250514',
            'max_tokens': 4000,
            'system': SYSTEM_PROMPT,
            'messages': [{'role': 'user', 'content': user_content}]
        },
        timeout=120
    )

    if response.status_code == 200:
        return response.json()['content'][0]['text']

    error_msg = f"Anthropic HTTP {response.status_code}"
    try:
        error_detail = response.json().get('error', {}).get('message', '')
        if error_detail:
            error_msg += f" - {error_detail}"
    except Exception:
        pass
    raise Exception(error_msg)


def call_openai(user_content):
    """Appel OpenAI GPT-4o (fallback 1)"""
    if not OPENAI_API_KEY:
        raise Exception("OpenAI: cle API non configuree")

    if isinstance(user_content, list):
        messages_content = []
        for item in user_content:
            if item.get('type') == 'text':
                messages_content.append({"type": "text", "text": item['text']})
            elif item.get('type') == 'document':
                messages_content.append({
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:{item['source']['media_type']};base64,{item['source']['data']}"
                    }
                })
    else:
        messages_content = user_content

    response = requests.post(
        'https://api.openai.com/v1/chat/completions',
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {OPENAI_API_KEY}'
        },
        json={
            'model': 'gpt-4o',
            'max_tokens': 4000,
            'messages': [
                {'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user', 'content': messages_content}
            ]
        },
        timeout=120
    )

    if response.status_code == 200:
        return response.json()['choices'][0]['message']['content']
    raise Exception(f"OpenAI HTTP {response.status_code}")


def call_ollama(text_content):
    """Appel Ollama local (fallback 2 - texte uniquement)"""
    if not text_content or not isinstance(text_content, str):
        raise Exception("Ollama: pas de texte disponible")

    prompt = f"{SYSTEM_PROMPT}\n\nAnalyse ce ticket de frais :\n\n{text_content}"

    try:
        response = requests.post(
            f'{OLLAMA_URL}/api/generate',
            json={
                'model': OLLAMA_MODEL,
                'prompt': prompt,
                'stream': False,
                'options': {'temperature': 0.1, 'num_predict': 4000}
            },
            timeout=180
        )
    except requests.exceptions.ConnectionError:
        raise Exception("Ollama: serveur non accessible")

    if response.status_code == 200:
        return response.json().get('response', '')
    raise Exception(f"Ollama HTTP {response.status_code}")


# ═══════════════════════════════════════════════════════════════════
# MOTEUR D'ANALYSE AVEC RETRY + FALLBACK
# ═══════════════════════════════════════════════════════════════════

def clean_json_response(text):
    """Nettoie et parse la réponse JSON"""
    text = re.sub(r'```json\s*', '', text)
    text = re.sub(r'```\s*', '', text).strip()
    json_match = re.search(r'\{.*\}', text, re.DOTALL)
    if json_match:
        text = json_match.group()
    return json.loads(text)


def analyze_ticket_with_retry(pdf_bytes, filename="ticket.pdf"):
    """Analyse avec fallback : Claude → OpenAI → Ollama"""
    text = extract_text_from_pdf(pdf_bytes)
    has_text = len(text.strip()) > 50

    if has_text:
        cloud_content = f"Analyse ce ticket de frais et produis les ecritures comptables :\n\n{text}"
    else:
        pdf_b64 = base64.b64encode(pdf_bytes).decode('utf-8')
        cloud_content = [
            {
                "type": "document",
                "source": {
                    "type": "base64",
                    "media_type": "application/pdf",
                    "data": pdf_b64
                }
            },
            {
                "type": "text",
                "text": "Analyse ce ticket de frais et produis les ecritures comptables. "
                        "Une page peut contenir plusieurs tickets, traite-les tous separement."
            }
        ]

    providers = []
    if ANTHROPIC_API_KEY:
        providers.append(("Claude", lambda c=cloud_content: call_anthropic(c)))
    if OPENAI_API_KEY:
        providers.append(("OpenAI", lambda c=cloud_content: call_openai(c)))
    if has_text:
        providers.append(("Ollama", lambda t=text: call_ollama(t)))

    if not providers:
        return {
            "exploitable": False,
            "raison_non_exploitable": "Aucun provider IA configure",
            "ecritures": []
        }

    last_error = ""
    for provider_name, provider_fn in providers:
        for attempt in range(MAX_RETRIES):
            try:
                print(f"  [{provider_name}] {filename} - tentative {attempt+1}/{MAX_RETRIES}")
                raw_response = provider_fn()
                result = clean_json_response(raw_response)
                if 'exploitable' not in result:
                    raise ValueError("JSON sans champ 'exploitable'")
                print(f"  [{provider_name}] {filename} - OK")
                return result

            except json.JSONDecodeError as e:
                last_error = f"{provider_name}: JSON invalide ({e})"
                print(f"  [{provider_name}] JSON invalide, retry...")
                time.sleep(RETRY_BASE_DELAY)

            except ValueError as e:
                last_error = f"{provider_name}: {e}"
                print(f"  [{provider_name}] {e}, retry...")
                time.sleep(RETRY_BASE_DELAY)

            except Exception as e:
                error_str = str(e)
                last_error = f"{provider_name}: {error_str}"
                print(f"  [{provider_name}] Erreur: {error_str}")

                if '429' in error_str:
                    wait = RATE_LIMIT_429_WAIT * (attempt + 1)
                    print(f"  [{provider_name}] Rate limit 429, attente {wait}s...")
                    time.sleep(wait)
                    continue
                if '529' in error_str:
                    wait = RETRY_BASE_DELAY * (attempt + 1) * 2
                    print(f"  [{provider_name}] Surcharge 529, attente {wait}s...")
                    time.sleep(wait)
                    continue
                if '400' in error_str:
                    print(f"  [{provider_name}] Erreur 400, provider suivant")
                    break
                time.sleep(RETRY_BASE_DELAY * (attempt + 1))

        print(f"  [{provider_name}] Echec apres {MAX_RETRIES} tentatives")

    return {
        "exploitable": False,
        "raison_non_exploitable": f"Analyse impossible: {last_error}",
        "ecritures": []
    }


# ═══════════════════════════════════════════════════════════════════
# GÉNÉRATION EXCEL SAGE
# ═══════════════════════════════════════════════════════════════════

def create_excel(all_ecritures, alerts=None):
    """Crée le fichier Excel format Sage"""
    wb = Workbook()
    ws = wb.active
    ws.title = "Ecritures comptables"

    header_font = Font(name='Calibri', bold=True, size=11, color='FFFFFF')
    header_fill = PatternFill(start_color='2C3E50', end_color='2C3E50', fill_type='solid')
    header_alignment = Alignment(horizontal='center', vertical='center')
    border = Border(
        left=Side(style='thin'), right=Side(style='thin'),
        top=Side(style='thin'), bottom=Side(style='thin')
    )

    headers = ['Date', 'Reference', 'Journal', 'Compte', 'Libelle', 'Debit', 'Credit']
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_alignment
        cell.border = border

    row = 2
    total_debit = 0
    total_credit = 0

    for e in all_ecritures:
        debit = round(float(e.get('debit', 0) or 0), 2)
        credit = round(float(e.get('credit', 0) or 0), 2)
        total_debit += debit
        total_credit += credit

        values = [
            e.get('date', ''),
            e.get('reference', ''),
            e.get('journal', 'FCB'),
            e.get('compte', ''),
            e.get('libelle', ''),
            debit,
            credit
        ]
        for col, val in enumerate(values, 1):
            cell = ws.cell(row=row, column=col, value=val)
            cell.border = border
            if col in (6, 7):
                cell.number_format = '#,##0.00'
                cell.alignment = Alignment(horizontal='right')
        row += 1

    row += 1
    equilibre = abs(total_debit - total_credit) < 0.01
    ctrl_fill = PatternFill(
        start_color='27AE60' if equilibre else 'E74C3C',
        end_color='27AE60' if equilibre else 'E74C3C',
        fill_type='solid'
    )
    ctrl_font = Font(name='Calibri', bold=True, color='FFFFFF')

    ws.cell(row=row, column=4, value='CONTROLE').font = ctrl_font
    ws.cell(row=row, column=4).fill = ctrl_fill
    status = 'OK - Equilibre' if equilibre else 'ERREUR - Desequilibre'
    ws.cell(row=row, column=5, value=status).font = ctrl_font
    ws.cell(row=row, column=5).fill = ctrl_fill
    ws.cell(row=row, column=6, value=round(total_debit, 2)).font = ctrl_font
    ws.cell(row=row, column=6).fill = ctrl_fill
    ws.cell(row=row, column=6).number_format = '#,##0.00'
    ws.cell(row=row, column=7, value=round(total_credit, 2)).font = ctrl_font
    ws.cell(row=row, column=7).fill = ctrl_fill
    ws.cell(row=row, column=7).number_format = '#,##0.00'

    if alerts:
        row += 2
        alert_font = Font(name='Calibri', bold=True, color='E74C3C')
        ws.cell(row=row, column=1, value='ALERTES').font = alert_font
        for alert in alerts:
            row += 1
            ws.cell(row=row, column=1, value=alert)

    for col_letter, width in [('A', 14), ('B', 12), ('C', 10), ('D', 12), ('E', 45), ('F', 14), ('G', 14)]:
        ws.column_dimensions[col_letter].width = width

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return output.read()


# ═══════════════════════════════════════════════════════════════════
# RAPPORT INEXPLOITABLES
# ═══════════════════════════════════════════════════════════════════

def create_inexploitable_report(inexploitable_tickets):
    """Crée un PDF listant les tickets inexploitables"""
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 18)
    c.setFillColor(red)
    c.drawString(50, height - 60, "Justificatifs inexploitables")
    c.setFont("Helvetica", 11)
    c.setFillColor(black)
    c.drawString(50, height - 85, f"Date de traitement : {datetime.now().strftime('%d/%m/%Y %H:%M')}")
    c.setFont("Helvetica", 10)
    c.drawString(50, height - 110, "Les documents suivants n'ont pas pu etre exploites.")
    c.drawString(50, height - 125, "Merci de fournir des justificatifs conformes.")

    y = height - 165
    c.setFont("Helvetica-Bold", 11)
    c.drawString(50, y, "Fichier")
    c.drawString(300, y, "Motif")
    y -= 5
    c.line(50, y, width - 50, y)
    y -= 20

    c.setFont("Helvetica", 10)
    for ticket in inexploitable_tickets:
        if y < 80:
            c.showPage()
            y = height - 60
        c.drawString(50, y, ticket['filename'][:35])
        c.drawString(300, y, ticket['raison'][:50])
        y -= 18

    c.save()
    buffer.seek(0)
    return buffer.read()


# ═══════════════════════════════════════════════════════════════════
# TRAITEMENT PRINCIPAL
# ═══════════════════════════════════════════════════════════════════

def process_tickets(files_data):
    """Traite une liste de tickets"""
    all_ecritures = []
    exploited_pdfs = []
    inexploitable_tickets = []
    alerts = []
    ticket_num = 1
    results_detail = []

    # Split multi-pages
    split_files = []
    for file_info in files_data:
        try:
            reader = PdfReader(io.BytesIO(file_info['bytes']))
            if len(reader.pages) > 1:
                print(f"  Split {file_info['filename']} : {len(reader.pages)} pages")
                pages = split_pdf_pages(file_info['bytes'], file_info['filename'])
                split_files.extend(pages)
            else:
                split_files.append(file_info)
        except Exception as e:
            print(f"  Erreur split {file_info['filename']}: {e}")
            split_files.append(file_info)

    total_pages = len(split_files)
    print(f"\n{'='*50}")
    print(f"Traitement de {total_pages} page(s)")
    print(f"{'='*50}\n")

    for idx, file_info in enumerate(split_files):
        filename = file_info['filename']
        pdf_bytes = file_info['bytes']

        print(f"\n[{idx+1}/{total_pages}] {filename}")
        result = analyze_ticket_with_retry(pdf_bytes, filename)

        if result.get('exploitable'):
            ecritures = result.get('ecritures', [])
            for e in ecritures:
                e['reference'] = f'T{ticket_num}'
                e['debit'] = round(float(e.get('debit', 0) or 0), 2)
                e['credit'] = round(float(e.get('credit', 0) or 0), 2)

            total_d = sum(e['debit'] for e in ecritures)
            total_c = sum(e['credit'] for e in ecritures)
            if abs(total_d - total_c) > 0.01:
                alerts.append(f"T{ticket_num} ({filename}) : Desequilibre ({total_d:.2f} != {total_c:.2f})")
                ligne_banque = next((e for e in ecritures if e['compte'] == '51200000'), None)
                if ligne_banque:
                    ligne_banque['credit'] = round(total_d, 2)

            all_ecritures.extend(ecritures)
            stamped = stamp_pdf_with_s(pdf_bytes)
            exploited_pdfs.append(stamped)
            results_detail.append({
                'filename': filename, 'status': 'exploitable',
                'reference': f'T{ticket_num}', 'ecritures': ecritures
            })
            ticket_num += 1
        else:
            raison = result.get('raison_non_exploitable', 'Document inexploitable')
            inexploitable_tickets.append({'filename': filename, 'raison': raison})
            alerts.append(f"!! {filename} : {raison}")
            results_detail.append({
                'filename': filename, 'status': 'inexploitable', 'raison': raison
            })

        if idx < total_pages - 1:
            time.sleep(RATE_LIMIT_DELAY)

    # Génération fichiers (supprimés automatiquement après FILE_RETENTION_MINUTES)
    output_files = {}
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    if all_ecritures:
        excel_bytes = create_excel(all_ecritures, alerts if alerts else None)
        excel_name = f'Sage_import_{timestamp}.xlsx'
        (OUTPUT_FOLDER / excel_name).write_bytes(excel_bytes)
        output_files['excel'] = {'name': excel_name, 'path': str(OUTPUT_FOLDER / excel_name)}

    if exploited_pdfs:
        merged = merge_pdfs(exploited_pdfs)
        stamped_name = f'Tickets_exploites_S_{timestamp}.pdf'
        (OUTPUT_FOLDER / stamped_name).write_bytes(merged)
        output_files['stamped_pdf'] = {'name': stamped_name, 'path': str(OUTPUT_FOLDER / stamped_name)}

    if inexploitable_tickets:
        report = create_inexploitable_report(inexploitable_tickets)
        report_name = f'Justificatifs_inexploites_{timestamp}.pdf'
        (OUTPUT_FOLDER / report_name).write_bytes(report)
        output_files['inexploitable_pdf'] = {'name': report_name, 'path': str(OUTPUT_FOLDER / report_name)}

    total_d = round(sum(e['debit'] for e in all_ecritures), 2)
    total_c = round(sum(e['credit'] for e in all_ecritures), 2)
    print(f"\n{'='*50}")
    print(f"RESULTAT : {len(exploited_pdfs)} exploites / {len(inexploitable_tickets)} inexploitables")
    print(f"TOTAUX   : D={total_d} | C={total_c} | {'OK' if abs(total_d - total_c) < 0.01 else 'ERREUR'}")
    print(f"{'='*50}\n")

    return {
        'output_files': output_files,
        'results_detail': results_detail,
        'summary': {
            'total': total_pages,
            'exploites': len(exploited_pdfs),
            'inexploites': len(inexploitable_tickets),
            'total_debit': total_d,
            'total_credit': total_c,
            'equilibre': abs(total_d - total_c) < 0.01
        }
    }


# ═══════════════════════════════════════════════════════════════════
# EMAIL (optionnel)
# ═══════════════════════════════════════════════════════════════════

def send_email_with_attachments(to_email, subject, body, attachments):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    for att_filename, file_bytes in attachments:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(file_bytes)
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{att_filename}"')
        msg.attach(part)
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)


def check_emails():
    while True:
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER)
            mail.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            mail.select('INBOX')
            _, messages = mail.search(None, 'UNSEEN')
            for num in messages[0].split():
                if not num:
                    continue
                _, msg_data = mail.fetch(num, '(RFC822)')
                msg = email.message_from_bytes(msg_data[0][1])
                sender = email.utils.parseaddr(msg['From'])[1]
                subject = msg['Subject'] or 'Sans objet'
                files_data = []
                for part in msg.walk():
                    if part.get_content_type() == 'application/pdf':
                        att_filename = part.get_filename() or 'document.pdf'
                        pdf_bytes = part.get_payload(decode=True)
                        if pdf_bytes:
                            files_data.append({'filename': att_filename, 'bytes': pdf_bytes})
                if not files_data:
                    continue
                print(f"\nMail de {sender} - {len(files_data)} PDF(s)")
                results = process_tickets(files_data)
                attachments = []
                files = results['output_files']
                for key in ['excel', 'stamped_pdf', 'inexploitable_pdf']:
                    if files.get(key):
                        with open(files[key]['path'], 'rb') as f:
                            attachments.append((files[key]['name'], f.read()))
                s = results['summary']
                body = f"""Bonjour,

Traitement de vos {s['total']} justificatif(s) termine.

- {s['exploites']} exploite(s)
- {s['inexploites']} inexploitable(s)
- Debit : {s['total_debit']:.2f} EUR
- Credit : {s['total_credit']:.2f} EUR
- Equilibre : {'OK' if s['equilibre'] else 'ERREUR'}

Agent Comptable IA"""
                send_email_with_attachments(sender, f"Re: {subject}", body, attachments)
                print(f"Reponse envoyee a {sender}")
            mail.logout()
        except Exception as e:
            print(f"Erreur email: {e}")
        time.sleep(CHECK_INTERVAL)


# ═══════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        ip = request.remote_addr

        if is_locked_out(ip):
            error = "Trop de tentatives. Reessayez dans 5 minutes."
        else:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

            if username == APP_USERNAME and check_password(password):
                session.permanent = True
                session['authenticated'] = True
                session['login_time'] = datetime.now().isoformat()
                session['csrf_token'] = secrets.token_hex(32)
                clear_attempts(ip)
                return redirect(url_for('index'))
            else:
                record_failed_attempt(ip)
                remaining = MAX_LOGIN_ATTEMPTS - LOGIN_ATTEMPTS.get(ip, [0])[0]
                if remaining > 0:
                    error = f"Identifiants incorrects. {remaining} tentative(s) restante(s)."
                else:
                    error = "Compte bloque pour 5 minutes."

    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    return render_template('index.html', csrf_token=generate_csrf_token())


@app.route('/api/process', methods=['POST'])
@login_required
def api_process():
    if 'files' not in request.files:
        return jsonify({'error': 'Aucun fichier envoye'}), 400

    files = request.files.getlist('files')
    if not files:
        return jsonify({'error': 'Aucun fichier selectionne'}), 400

    files_data = []
    for f in files:
        if f.filename and f.filename.lower().endswith('.pdf'):
            safe_name = sanitize_filename(f.filename)
            pdf_bytes = f.read()

            # Validation : vérifier que c'est bien un PDF
            if not pdf_bytes[:5] == b'%PDF-':
                continue

            files_data.append({'filename': safe_name, 'bytes': pdf_bytes})

    if not files_data:
        return jsonify({'error': 'Aucun fichier PDF valide'}), 400

    try:
        results = process_tickets(files_data)

        # Nettoyage immédiat des données en mémoire
        for fd in files_data:
            fd['bytes'] = None
        files_data.clear()

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/download/<filename>')
@login_required
def download_file(filename):
    # Anti path-traversal
    safe_name = sanitize_filename(filename)
    filepath = OUTPUT_FOLDER / safe_name

    if not filepath.exists():
        return jsonify({'error': 'Fichier non trouve'}), 404

    # Vérifier que le fichier est bien dans OUTPUT_FOLDER
    try:
        filepath.resolve().relative_to(OUTPUT_FOLDER.resolve())
    except ValueError:
        abort(403)

    @after_this_request
    def remove_file(response):
        """Supprime le fichier après envoi"""
        try:
            filepath.unlink()
            print(f"  [ZDR] Fichier supprime apres download: {safe_name}")
        except Exception:
            pass
        return response

    return send_file(filepath, as_attachment=True, download_name=safe_name)


@app.route('/api/status')
@login_required
def api_status():
    providers = {
        'anthropic': bool(ANTHROPIC_API_KEY),
        'openai': bool(OPENAI_API_KEY),
        'ollama': False
    }
    try:
        r = requests.get(f'{OLLAMA_URL}/api/tags', timeout=3)
        providers['ollama'] = r.status_code == 200
    except Exception:
        pass

    return jsonify({
        'providers': providers,
        'active_providers': sum(1 for v in providers.values() if v),
        'file_retention_minutes': FILE_RETENTION_MINUTES
    })


# ═══════════════════════════════════════════════════════════════════
# DÉMARRAGE
# ═══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("\n" + "="*50)
    print("  AGENT COMPTABLE IA v4.0 SECURE")
    print("="*50)

    print("\nSecurite :")
    print(f"  Login         : {APP_USERNAME} / {'hash' if APP_PASSWORD_HASH else 'plain'}")
    print(f"  Session       : {app.config['PERMANENT_SESSION_LIFETIME']}")
    print(f"  CSRF          : actif")
    print(f"  Anti-bruteforce: {MAX_LOGIN_ATTEMPTS} tentatives, lockout {LOCKOUT_DURATION}s")
    print(f"  Zero Data     : fichiers supprimes apres {FILE_RETENTION_MINUTES} min")
    print(f"  Headers       : CSP, X-Frame-Options, nosniff, no-cache")

    print("\nProviders :")
    print(f"  Claude  : {'OK' if ANTHROPIC_API_KEY else 'NON'}")
    print(f"  OpenAI  : {'OK' if OPENAI_API_KEY else 'NON'}")
    try:
        r = requests.get(f'{OLLAMA_URL}/api/tags', timeout=3)
        print(f"  Ollama  : {'OK - ' + OLLAMA_MODEL if r.status_code == 200 else 'NON'}")
    except Exception:
        print(f"  Ollama  : NON ({OLLAMA_URL})")

    if EMAIL_ADDRESS and EMAIL_PASSWORD:
        email_thread = threading.Thread(target=check_emails, daemon=True)
        email_thread.start()
        print(f"\nEmail : {EMAIL_ADDRESS}")
    else:
        print("\nEmail : non configure")

    # Thread de nettoyage automatique
    cleanup_thread = threading.Thread(target=schedule_cleanup, daemon=True)
    cleanup_thread.start()

    print(f"\nInterface : http://localhost:5000")
    print("="*50 + "\n")

    app.run(host='0.0.0.0', port=5000, debug=False)