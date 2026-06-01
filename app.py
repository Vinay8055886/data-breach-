from flask import Flask, render_template, request, jsonify
import subprocess
import threading
import uuid
import re
import os

app = Flask(__name__, template_folder='templates', static_folder='static')

# ─── In-Memory Job Store ───────────────────────────────────────────────────────
# Structure: { job_id: { 'status': 'running'|'complete', 'h8mail': {...}, 'cr3dover': {...} } }
jobs = {}
jobs_lock = threading.Lock()

# ─── Helper: Strip ANSI color codes from tool output ──────────────────────────
def strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

# ─── Helper: Mark job complete when both tools are done ───────────────────────
def check_job_complete(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return
        h8_done = job.get('h8mail', {}).get('status') in ('done', 'error', 'timeout')
        cr_done = job.get('cr3dover', {}).get('status') in ('done', 'error', 'timeout')
        if h8_done and cr_done:
            jobs[job_id]['status'] = 'complete'

# ─── Background Worker: h8mail ────────────────────────────────────────────────
def run_h8mail(email, job_id):
    try:
        process = subprocess.run(
            ['h8mail', '-t', email],
            capture_output=True, text=True, timeout=60
        )
        output = strip_ansi(process.stdout + process.stderr)
        with jobs_lock:
            jobs[job_id]['h8mail'] = {'status': 'done', 'output': output}
    except subprocess.TimeoutExpired:
        with jobs_lock:
            jobs[job_id]['h8mail'] = {
                'status': 'timeout',
                'output': 'h8mail timed out after 60 seconds.'
            }
    except FileNotFoundError:
        with jobs_lock:
            jobs[job_id]['h8mail'] = {
                'status': 'error',
                'output': 'h8mail is not installed. Run: pip install h8mail'
            }
    except Exception as e:
        with jobs_lock:
            jobs[job_id]['h8mail'] = {'status': 'error', 'output': str(e)}
    check_job_complete(job_id)

# ─── Background Worker: Cr3dOv3r ─────────────────────────────────────────────
def run_cr3dover(email, job_id):
    # Cr3dOv3r is a cloned Python script: expects ./Cr3dOv3r/Cr3dOv3r.py in project root
    cr3dover_path = os.path.join(os.path.dirname(__file__), 'Cr3dOv3r', 'Cr3dOv3r.py')
    try:
        process = subprocess.run(
            ['python', cr3dover_path, '-e', email, '-p'],
            capture_output=True, text=True, timeout=90
        )
        output = strip_ansi(process.stdout + process.stderr)
        with jobs_lock:
            jobs[job_id]['cr3dover'] = {'status': 'done', 'output': output}
    except subprocess.TimeoutExpired:
        with jobs_lock:
            jobs[job_id]['cr3dover'] = {
                'status': 'timeout',
                'output': 'Cr3dOv3r timed out after 90 seconds.'
            }
    except FileNotFoundError:
        with jobs_lock:
            jobs[job_id]['cr3dover'] = {
                'status': 'error',
                'output': 'Cr3dOv3r not found. Clone it: git clone https://github.com/D4Vinci/Cr3dOv3r.git'
            }
    except Exception as e:
        with jobs_lock:
            jobs[job_id]['cr3dover'] = {'status': 'error', 'output': str(e)}
    check_job_complete(job_id)

# ─── Known breach database for enrichment ────────────────────────────────────
KNOWN_BREACHES = {
    'linkedin':   {'name': 'LinkedIn',   'year': '2021', 'data': ['Email', 'Phone', 'Name', 'Job Info']},
    'adobe':      {'name': 'Adobe',      'year': '2013', 'data': ['Email', 'Password Hash', 'Username']},
    'canva':      {'name': 'Canva',      'year': '2019', 'data': ['Email', 'Name', 'City', 'Password']},
    'facebook':   {'name': 'Facebook',   'year': '2019', 'data': ['Phone', 'Email', 'Name', 'Location']},
    'twitter':    {'name': 'Twitter',    'year': '2022', 'data': ['Email', 'Phone']},
    'dropbox':    {'name': 'Dropbox',    'year': '2012', 'data': ['Email', 'Password Hash']},
    'myspace':    {'name': 'MySpace',    'year': '2016', 'data': ['Email', 'Password', 'Username']},
    'yahoo':      {'name': 'Yahoo',      'year': '2016', 'data': ['Email', 'Password Hash', 'DOB', 'Security Q&A']},
    'ebay':       {'name': 'eBay',       'year': '2014', 'data': ['Email', 'Password', 'Name', 'Address']},
    'tumblr':     {'name': 'Tumblr',     'year': '2013', 'data': ['Email', 'Password Hash']},
    'collection': {'name': 'Collection #1', 'year': '2019', 'data': ['Email', 'Password (plaintext)']},
    'exploit':    {'name': 'Exploit.in', 'year': '2017', 'data': ['Email', 'Password']},
    'antipublic': {'name': 'AntiPublic', 'year': '2016', 'data': ['Email', 'Password']},
    'breach':     {'name': 'Data Breach', 'year': 'Unknown', 'data': ['Email', 'Credentials']},
}

def enrich_breach(line, tool):
    """Extract structured details from a raw breach line."""
    line_lower = line.lower()

    # Determine source
    source = 'Unknown Source'
    year   = 'Unknown'
    data_types = []

    for key, info in KNOWN_BREACHES.items():
        if key in line_lower:
            source     = info['name']
            year       = info['year']
            data_types = info['data']
            break

    # Detect data types from line content if not enriched
    if not data_types:
        if 'password' in line_lower:    data_types.append('Password')
        if 'hash' in line_lower:        data_types.append('Password Hash')
        if 'email' in line_lower:       data_types.append('Email')
        if 'phone' in line_lower:       data_types.append('Phone')
        if 'username' in line_lower:    data_types.append('Username')
        if 'name' in line_lower:        data_types.append('Name')
        if ':' in line and '@' in line: data_types.append('Email + Password combo')
        if not data_types:              data_types.append('Personal Data')

    # Severity
    high_risk = any(d in data_types for d in ['Password', 'Password Hash', 'Email + Password combo'])
    severity  = 'HIGH' if high_risk else 'MEDIUM'

    return {
        'source':     source,
        'year':       year,
        'data_types': data_types,
        'severity':   severity,
        'tool':       tool,
        'raw':        line.strip()
    }

# ─── Helper: Parse raw outputs into structured breach findings ────────────────
BOILERPLATE_H8 = ['h8mail', 'searching', 'target', 'start', 'finish', 'version',
                  'checking', 'running', 'using', 'config', '[*]', '[-]', 'warning']
BOILERPLATE_CR = ['cr3dover', 'checking', 'testing', 'starting', 'searching',
                  'loading', 'done', 'finished', 'error', 'warning', '[*]', '[-]']

def parse_results(job):
    findings = []
    breached = False

    # ── h8mail ────────────────────────────────────────────────────────────────
    if job.get('h8mail', {}).get('status') == 'done':
        for line in job['h8mail'].get('output', '').split('\n'):
            line = line.strip()
            if len(line) < 10: continue
            is_hit = (
                ('[+]' in line and any(k in line.lower() for k in ['breach','password','source','hash']))
                or ('password' in line.lower() and ':' in line)
                or ('hash' in line.lower() and len(line) > 30)
            )
            is_junk = any(k in line.lower() for k in BOILERPLATE_H8)
            if is_hit and not is_junk:
                findings.append(enrich_breach(line, 'h8mail'))
                breached = True

    # ── Cr3dOv3r ─────────────────────────────────────────────────────────────
    if job.get('cr3dover', {}).get('status') == 'done':
        for line in job['cr3dover'].get('output', '').split('\n'):
            line = line.strip()
            if len(line) < 10: continue
            is_hit = (
                (':' in line and '@' in line and len(line) > 15)
                or ('password' in line.lower() and ':' in line)
                or ('[+]' in line)
            )
            is_junk = any(k in line.lower() for k in BOILERPLATE_CR)
            if is_hit and not is_junk:
                findings.append(enrich_breach(line, 'Cr3dOv3r'))
                breached = True

    return breached, findings[:15]

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/check', methods=['POST'])
def check_breach():
    data = request.json
    query = data.get('query', '').strip()

    # Validate email format to prevent command injection
    if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', query):
        return jsonify({'error': 'Please enter a valid email address.'})

    # Create a unique job ID
    job_id = str(uuid.uuid4())
    with jobs_lock:
        jobs[job_id] = {
            'status': 'running',
            'email': query,
            'h8mail':   {'status': 'pending', 'output': ''},
            'cr3dover': {'status': 'pending', 'output': ''}
        }

    # Launch both tools in parallel background threads
    threading.Thread(target=run_h8mail,   args=(query, job_id), daemon=True).start()
    threading.Thread(target=run_cr3dover, args=(query, job_id), daemon=True).start()

    return jsonify({'job_id': job_id})

@app.route('/status/<job_id>', methods=['GET'])
def job_status(job_id):
    with jobs_lock:
        job = jobs.get(job_id)

    if not job:
        return jsonify({'error': 'Job not found.'}), 404

    response = {
        'status':          job['status'],
        'h8mail_status':   job['h8mail'].get('status', 'pending'),
        'cr3dover_status': job['cr3dover'].get('status', 'pending'),
    }

    if job['status'] == 'complete':
        breached, findings = parse_results(job)
        response['leaked']   = breached
        response['count']    = len(findings)
        response['findings'] = findings

    return jsonify(response)

# ── Debug: view raw tool output (open in browser: /debug/<job_id>) ────────────
@app.route('/debug/<job_id>', methods=['GET'])
def debug_job(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found.'}), 404
    return jsonify({
        'status':   job['status'],
        'h8mail':   job.get('h8mail', {}),
        'cr3dover': job.get('cr3dover', {}),
    })

if __name__ == '__main__':
    app.run(debug=True)
