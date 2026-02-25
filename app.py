"""
Agent Comptable IA - MVP
Traitement automatique de tickets de frais → écritures comptables Sage
"""

import os
import io
import json
import base64
import re
import email
import imaplib
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from pathlib import Path

import requests
from flask import Flask, request, jsonify, render_template, send_file
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import red, black
from reportlab.lib.pagesizes import A4
import fitz  # PyMuPDF for text extraction

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max

# ─── Configuration ───────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', 'VOTRE_CLE_API_ICI')
UPLOAD_FOLDER = Path('uploads')
OUTPUT_FOLDER = Path('outputs')
UPLOAD_FOLDER.mkdir(exist_ok=True)
OUTPUT_FOLDER.mkdir(exist_ok=True)

# ─── Config Email (optionnel) ────────────────────────────────────
EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS', 'ton-email@gmail.com')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', 'ton-mot-de-passe-application')
IMAP_SERVER = 'imap.gmail.com'
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 465
CHECK_INTERVAL = 30

# ─── Prompt Comptable ────────────────────────────────────────────
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

IMPORTANT : Une page peut contenir PLUSIEURS tickets côte à côte ou empilés. Analyse CHAQUE ticket séparément et produis une écriture par ticket.

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
        page_bytes = output.read()

        page_name = f"{Path(filename).stem}_page{i+1}.pdf"
        pages.append({'filename': page_name, 'bytes': page_bytes, 'original_filename': filename})

    return pages


def analyze_ticket_with_claude(pdf_bytes, filename="ticket.pdf"):
    """Envoie un ticket à Claude pour analyse comptable"""
    text = extract_text_from_pdf(pdf_bytes)

    if len(text.strip()) > 50:
        user_content = f"Analyse ce ticket de frais et produis les écritures comptables :\n\n{text}"
    else:
        pdf_b64 = base64.b64encode(pdf_bytes).decode('utf-8')
        user_content = [
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
                "text": "Analyse ce ticket de frais et produis les écritures comptables. Une page peut contenir plusieurs tickets, traite-les tous séparément."
            }
        ]

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

    if response.status_code != 200:
        return {"exploitable": False, "raison_non_exploitable": f"Erreur API ({response.status_code})", "ecritures": []}

    result_text = response.json()['content'][0]['text']
    result_text = re.sub(r'```json\s*', '', result_text)
    result_text = re.sub(r'```\s*', '', result_text).strip()

    try:
        return json.loads(result_text)
    except json.JSONDecodeError:
        return {"exploitable": False, "raison_non_exploitable": "Réponse IA invalide", "ecritures": []}


def stamp_pdf_with_s(pdf_bytes):
    """Ajoute un 'S' rouge sur le PDF"""
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


def create_excel(all_ecritures, alerts=None):
    """Crée le fichier Excel format Sage"""
    wb = Workbook()
    ws = wb.active
    ws.title = "Ecritures comptables"

    header_font = Font(name='Calibri', bold=True, size=11, color='FFFFFF')
    header_fill = PatternFill(start_color='2C3E50', end_color='2C3E50', fill_type='solid')
    header_alignment = Alignment(horizontal='center', vertical='center')
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
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
    ctrl_fill = PatternFill(
        start_color='27AE60' if abs(total_debit - total_credit) < 0.01 else 'E74C3C',
        end_color='27AE60' if abs(total_debit - total_credit) < 0.01 else 'E74C3C',
        fill_type='solid'
    )
    ctrl_font = Font(name='Calibri', bold=True, color='FFFFFF')

    ws.cell(row=row, column=4, value='CONTROLE').font = ctrl_font
    ws.cell(row=row, column=4).fill = ctrl_fill

    status = 'OK - Equilibre' if abs(total_debit - total_credit) < 0.01 else 'ERREUR - Desequilibre'
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

    ws.column_dimensions['A'].width = 14
    ws.column_dimensions['B'].width = 12
    ws.column_dimensions['C'].width = 10
    ws.column_dimensions['D'].width = 12
    ws.column_dimensions['E'].width = 45
    ws.column_dimensions['F'].width = 14
    ws.column_dimensions['G'].width = 14

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return output.read()


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
    c.drawString(50, height - 110, "Les documents suivants n'ont pas pu etre exploites pour la saisie comptable.")
    c.drawString(50, height - 125, "Merci de fournir des justificatifs conformes (facture detaillee avec HT, TVA et TTC).")

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


def process_tickets(files_data):
    """Traite une liste de tickets et retourne les résultats"""
    all_ecritures = []
    exploited_pdfs = []
    inexploitable_tickets = []
    alerts = []
    ticket_num = 1
    results_detail = []

    # Découper les PDFs multi-pages en pages individuelles
    split_files = []
    for file_info in files_data:
        reader = PdfReader(io.BytesIO(file_info['bytes']))
        if len(reader.pages) > 1:
            pages = split_pdf_pages(file_info['bytes'], file_info['filename'])
            split_files.extend(pages)
        else:
            split_files.append(file_info)

    for file_info in split_files:
        filename = file_info['filename']
        pdf_bytes = file_info['bytes']

        result = analyze_ticket_with_claude(pdf_bytes, filename)

        if result.get('exploitable'):
            ecritures = result.get('ecritures', [])

            for e in ecritures:
                e['reference'] = f'T{ticket_num}'
                e['debit'] = round(float(e.get('debit', 0) or 0), 2)
                e['credit'] = round(float(e.get('credit', 0) or 0), 2)

            total_d = sum(e['debit'] for e in ecritures)
            total_c = sum(e['credit'] for e in ecritures)
            if abs(total_d - total_c) > 0.01:
                alerts.append(f"T{ticket_num} ({filename}) : Desequilibre detecte ({total_d:.2f} != {total_c:.2f})")
                ligne_banque = next((e for e in ecritures if e['compte'] == '51200000'), None)
                if ligne_banque:
                    ligne_banque['credit'] = round(total_d, 2)

            all_ecritures.extend(ecritures)

            stamped = stamp_pdf_with_s(pdf_bytes)
            exploited_pdfs.append(stamped)

            results_detail.append({
                'filename': filename,
                'status': 'exploitable',
                'reference': f'T{ticket_num}',
                'ecritures': ecritures
            })

            ticket_num += 1
        else:
            raison = result.get('raison_non_exploitable', 'Document inexploitable')
            inexploitable_tickets.append({'filename': filename, 'raison': raison})
            alerts.append(f"!! {filename} : {raison}")

            results_detail.append({
                'filename': filename,
                'status': 'inexploitable',
                'raison': raison
            })

    output_files = {}
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    if all_ecritures:
        excel_bytes = create_excel(all_ecritures, alerts if alerts else None)
        excel_name = f'Sage_import_{timestamp}.xlsx'
        output_path = OUTPUT_FOLDER / excel_name
        output_path.write_bytes(excel_bytes)
        output_files['excel'] = {'name': excel_name, 'path': str(output_path)}

    if exploited_pdfs:
        merged_stamped = merge_pdfs(exploited_pdfs)
        stamped_name = f'Tickets_exploites_S_{timestamp}.pdf'
        output_path = OUTPUT_FOLDER / stamped_name
        output_path.write_bytes(merged_stamped)
        output_files['stamped_pdf'] = {'name': stamped_name, 'path': str(output_path)}

    if inexploitable_tickets:
        report = create_inexploitable_report(inexploitable_tickets)
        report_name = f'Justificatifs_inexploites_{timestamp}.pdf'
        output_path = OUTPUT_FOLDER / report_name
        output_path.write_bytes(report)
        output_files['inexploitable_pdf'] = {'name': report_name, 'path': str(output_path)}

    return {
        'output_files': output_files,
        'results_detail': results_detail,
        'summary': {
            'total': len(split_files),
            'exploites': len(exploited_pdfs),
            'inexploites': len(inexploitable_tickets),
            'total_debit': round(sum(e['debit'] for e in all_ecritures), 2),
            'total_credit': round(sum(e['credit'] for e in all_ecritures), 2),
            'equilibre': abs(sum(e['debit'] for e in all_ecritures) - sum(e['credit'] for e in all_ecritures)) < 0.01
        }
    }


# ─── Email Functions ─────────────────────────────────────────────

import threading
import time


def send_email_with_attachments(to_email, subject, body, attachments):
    """Envoie un email avec pièces jointes"""
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
    """Vérifie les nouveaux emails et traite les PDFs"""
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

                print(f"Mail de {sender} - {len(files_data)} PDF(s) a traiter")

                results = process_tickets(files_data)

                attachments = []
                files = results['output_files']

                if files.get('excel'):
                    with open(files['excel']['path'], 'rb') as f:
                        attachments.append((files['excel']['name'], f.read()))

                if files.get('stamped_pdf'):
                    with open(files['stamped_pdf']['path'], 'rb') as f:
                        attachments.append((files['stamped_pdf']['name'], f.read()))

                if files.get('inexploitable_pdf'):
                    with open(files['inexploitable_pdf']['path'], 'rb') as f:
                        attachments.append((files['inexploitable_pdf']['name'], f.read()))

                s = results['summary']
                body = f"""Bonjour,

Traitement automatique de vos {s['total']} justificatif(s) termine.

Resultat :
- {s['exploites']} ticket(s) exploite(s)
- {s['inexploites']} ticket(s) inexploitable(s)
- Total debit : {s['total_debit']:.2f} EUR
- Total credit : {s['total_credit']:.2f} EUR
- Equilibre : {'OK' if s['equilibre'] else 'ERREUR'}

Fichiers joints :
{('- ' + files['excel']['name'] + ' (import Sage)') if files.get('excel') else ''}
{('- ' + files['stamped_pdf']['name'] + ' (tickets vises S)') if files.get('stamped_pdf') else ''}
{('- ' + files['inexploitable_pdf']['name'] + ' (a corriger)') if files.get('inexploitable_pdf') else ''}

Cordialement,
Agent Comptable IA"""

                send_email_with_attachments(
                    sender,
                    f"Re: {subject} - Ecritures comptables traitees",
                    body,
                    attachments
                )

                print(f"Reponse envoyee a {sender}")

            mail.logout()
        except Exception as e:
            print(f"Erreur email: {e}")

        time.sleep(CHECK_INTERVAL)


# ─── Routes Flask ────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/process', methods=['POST'])
def api_process():
    if 'files' not in request.files:
        return jsonify({'error': 'Aucun fichier envoye'}), 400

    files = request.files.getlist('files')
    if not files:
        return jsonify({'error': 'Aucun fichier selectionne'}), 400

    files_data = []
    for f in files:
        if f.filename and f.filename.lower().endswith('.pdf'):
            pdf_bytes = f.read()
            files_data.append({'filename': f.filename, 'bytes': pdf_bytes})

    if not files_data:
        return jsonify({'error': 'Aucun fichier PDF trouve'}), 400

    try:
        results = process_tickets(files_data)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/download/<filename>')
def download_file(filename):
    filepath = OUTPUT_FOLDER / filename
    if filepath.exists():
        return send_file(filepath, as_attachment=True, download_name=filename)
    return jsonify({'error': 'Fichier non trouve'}), 404


if __name__ == '__main__':
    if EMAIL_ADDRESS != 'ton-email@gmail.com':
        email_thread = threading.Thread(target=check_emails, daemon=True)
        email_thread.start()
        print(f"Surveillance email activee pour {EMAIL_ADDRESS}")
    else:
        print("Email non configure - mode web uniquement")

    print("Interface web sur http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)