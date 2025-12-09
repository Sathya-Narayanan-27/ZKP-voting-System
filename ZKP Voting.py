import random
import hashlib
import sqlite3
from flask import Flask, render_template_string, request, session, redirect, url_for, jsonify

app = Flask(__name__)
app.secret_key = 'super_secret_voting_key' # Change this for production

# --- DATABASE CONFIGURATION ---
DATABASE = 'voting_system.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, public_key TEXT NOT NULL, role TEXT NOT NULL, has_voted INTEGER NOT NULL DEFAULT 0, region_assigned TEXT);''')
    conn.execute('''CREATE TABLE IF NOT EXISTS elections (region TEXT NOT NULL, candidate TEXT NOT NULL, votes INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (region, candidate));''')
    conn.execute('''CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);''')
    try:
        conn.execute("ALTER TABLE users ADD COLUMN region_assigned TEXT")
    except sqlite3.OperationalError:
        pass 
    conn.execute('INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)', ('election_status', 'active'))
    conn.commit()
    conn.close()

init_db()

# --- CRYPTOGRAPHIC PARAMETERS ---
PRIME_P = 4276521769 
GENERATOR_G = 2
login_challenges = {}

# --- HELPER FUNCTIONS ---
def get_hash_int(text):
    return int(hashlib.sha256(text.encode('utf-8')).hexdigest(), 16) % (PRIME_P - 1)

def get_election_status(conn):
    status_row = conn.execute('SELECT value FROM config WHERE key = "election_status"').fetchone()
    return status_row['value'] if status_row else 'active'

def get_election_config(conn):
    """Fetches configuration for admin views. Returns: regions_config (dict) and regions_list (list)."""
    elections_data = conn.execute('SELECT region, candidate FROM elections ORDER BY region, candidate').fetchall()
    regions_config = {}
    regions_list = []
    
    for row in elections_data:
        region = row['region']
        if region not in regions_config:
            regions_config[region] = []
            regions_list.append(region)
        # Only include actual candidates, not placeholders
        if row['candidate'] != "No Candidate Yet":
            regions_config[region].append(row['candidate'])
    
    return regions_config, regions_list

def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user' not in session: return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def admin_required(f):
    def wrapper(*args, **kwargs):
        if 'user' not in session or session.get('role') != 'admin': return "Access Denied", 403
        return login_required(f)(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

# --- AUTH ROUTES ---
@app.route('/')
def home(): return render_template_string(HTML_TEMPLATE, page='home', p=PRIME_P, g=GENERATOR_G)

@app.route('/register_page')
def register_page(): return render_template_string(HTML_TEMPLATE, page='register', p=PRIME_P, g=GENERATOR_G)

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.json
    username = data.get('username')
    public_key = data.get('y')
    conn = get_db_connection()
    if conn.execute('SELECT username FROM users WHERE username = ?', (username,)).fetchone():
        conn.close()
        return jsonify({'status': 'error', 'message': 'User exists'})
    role = 'admin' if username == 'admin' else 'user'
    try:
        conn.execute('INSERT INTO users (username, public_key, role, has_voted) VALUES (?, ?, ?, ?)', (username, public_key, role, 0))
        conn.commit()
        return jsonify({'status': 'success'})
    except sqlite3.Error as e: return jsonify({'status': 'error', 'message': str(e)})
    finally: conn.close()

@app.route('/login_page')
def login_page(): return render_template_string(HTML_TEMPLATE, page='login', p=PRIME_P, g=GENERATOR_G)

@app.route('/api/login/step1', methods=['POST'])
def login_step1():
    data = request.json
    username = data.get('username')
    t = int(data.get('t'))
    conn = get_db_connection()
    user = conn.execute('SELECT public_key, role FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if not user: return jsonify({'status': 'error', 'message': 'User not found'})
    session['temp_public_key'] = user['public_key']
    session['temp_role'] = user['role']
    c = random.randint(1, 100)
    login_challenges[username] = {'t': t, 'c': c}
    return jsonify({'status': 'continue', 'c': c})

@app.route('/api/login/step2', methods=['POST'])
def login_step2():
    data = request.json
    username = data.get('username')
    s = int(data.get('s')) 
    if username not in login_challenges: return jsonify({'status': 'error', 'message': 'Session expired'})
    challenge_data = login_challenges.pop(username)
    t = challenge_data['t']; c = challenge_data['c']
    y = int(session.pop('temp_public_key')) 
    role = session.pop('temp_role')
    if pow(GENERATOR_G, s, PRIME_P) == (t * pow(y, c, PRIME_P)) % PRIME_P:
        session['user'] = username; session['role'] = role
        return jsonify({'status': 'success', 'redirect': url_for('dashboard')})
    return jsonify({'status': 'error', 'message': 'ZKP Failed'})

# --- DASHBOARD & VOTING ---
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    status = get_election_status(conn)
    results = conn.execute('SELECT region, candidate, votes FROM elections ORDER BY region, votes DESC').fetchall()
    votes_data = {}
    for row in results:
        if row['region'] not in votes_data: votes_data[row['region']] = []
        if row['candidate'] != "No Candidate Yet": votes_data[row['region']].append({'candidate': row['candidate'], 'votes': row['votes']})
    
    user_row = conn.execute('SELECT has_voted, region_assigned, role FROM users WHERE username = ?', (session['user'],)).fetchone()
    has_voted = user_row['has_voted'] if user_row else 1
    region_assigned = user_row['region_assigned'] if user_row else None
    role = user_row['role']
    conn.close()

    if role == 'admin':
        return render_template_string(HTML_TEMPLATE, page='admin_dashboard', votes=votes_data, election_status=status, p=PRIME_P, g=GENERATOR_G)
    
    # Normal User Logic
    if status == 'published':
        final_results = {}
        for region, candidates in votes_data.items():
            if not candidates: continue
            max_votes = candidates[0]['votes']
            winners = [c['candidate'] for c in candidates if c['votes'] == max_votes and c['votes'] > 0]
            final_results[region] = {'candidates': candidates, 'winners': winners, 'max_votes': max_votes}
        return render_template_string(HTML_TEMPLATE, page='final_results', final_results=final_results, user=session['user'])
    elif status == 'ended':
         return render_template_string(HTML_TEMPLATE, page='voting_dashboard', has_voted=1, user=session['user'], error_message="Election ended. Results pending publication.", regions={})
    else: 
        if not region_assigned: return render_template_string(HTML_TEMPLATE, page='voting_dashboard', has_voted=1, user=session['user'], error_message="No region assigned.", regions={})
        assigned_candidates = votes_data.get(region_assigned, [])
        if not assigned_candidates: return render_template_string(HTML_TEMPLATE, page='voting_dashboard', has_voted=1, user=session['user'], error_message="No candidates in your region.", regions={})
        regions_filtered = { region_assigned: [c['candidate'] for c in assigned_candidates] }
        return render_template_string(HTML_TEMPLATE, page='voting_dashboard', regions=regions_filtered, has_voted=has_voted, user=session['user'], assigned_region=region_assigned, p=PRIME_P, g=GENERATOR_G)

@app.route('/vote', methods=['POST'])
@login_required
def vote():
    conn = get_db_connection()
    if get_election_status(conn) != 'active': conn.close(); return "Voting inactive", 403
    if session['role'] != 'user': conn.close(); return "User only", 403
    user_row = conn.execute('SELECT has_voted, region_assigned FROM users WHERE username = ?', (session['user'],)).fetchone()
    if user_row['has_voted']: conn.close(); return "Already voted"
    region = request.form.get('region'); candidate = request.form.get('candidate')
    if region != user_row['region_assigned']: conn.close(); return "Wrong region", 403
    try:
        conn.execute('UPDATE elections SET votes = votes + 1 WHERE region = ? AND candidate = ?', (region, candidate))
        conn.execute('UPDATE users SET has_voted = 1 WHERE username = ?', (session['user'],))
        conn.commit()
    finally: conn.close()
    return redirect(url_for('dashboard'))

# --- ADMIN ROUTES ---
@app.route('/admin/manage')
@admin_required
def admin_manage():
    conn = get_db_connection()
    status = get_election_status(conn)
    conn.close()
    return render_template_string(HTML_TEMPLATE, page='admin_navigation', election_status=status, p=PRIME_P, g=GENERATOR_G)

@app.route('/admin/change_status', methods=['POST'])
@admin_required
def admin_change_status():
    action = request.form.get('action')
    conn = get_db_connection()
    try:
        if action == 'start_new':
            conn.execute('UPDATE config SET value = "active" WHERE key = "election_status"')
            conn.execute('UPDATE elections SET votes = 0')
            conn.execute('UPDATE users SET has_voted = 0')
        elif action == 'end': conn.execute('UPDATE config SET value = "ended" WHERE key = "election_status"')
        elif action == 'publish': conn.execute('UPDATE config SET value = "published" WHERE key = "election_status"')
        conn.commit()
    finally: conn.close()
    return redirect(url_for('admin_manage'))

@app.route('/admin/manage_regions')
@admin_required
def admin_manage_regions():
    conn = get_db_connection()
    _, regions_list = get_election_config(conn)
    conn.close()
    return render_template_string(HTML_TEMPLATE, page='admin_regions', regions_list=regions_list)

@app.route('/admin/add_region', methods=['POST'])
@admin_required
def admin_add_region():
    region = request.form.get('region_name').strip()
    if region:
        conn = get_db_connection()
        conn.execute('INSERT OR IGNORE INTO elections (region, candidate, votes) VALUES (?, ?, ?)', (region, 'No Candidate Yet', 0))
        conn.commit(); conn.close()
    return redirect(url_for('admin_manage_regions'))

@app.route('/admin/remove_region', methods=['POST'])
@admin_required
def admin_remove_region():
    region = request.form.get('region')
    if region:
        conn = get_db_connection()
        conn.execute('DELETE FROM elections WHERE region = ?', (region,))
        conn.commit(); conn.close()
    return redirect(url_for('admin_manage_regions'))

@app.route('/admin/manage_candidates')
@admin_required
def admin_manage_candidates():
    conn = get_db_connection()
    # CRITICAL FIX: Ensure this function is called and results passed to template
    regions_config, regions_list = get_election_config(conn)
    conn.close()
    return render_template_string(HTML_TEMPLATE, page='admin_candidates', regions_config=regions_config, regions_list=regions_list)

@app.route('/admin/add_candidate', methods=['POST'])
@admin_required
def admin_add_candidate():
    region = request.form.get('region'); candidate = request.form.get('candidate_name').strip()
    if region and candidate:
        conn = get_db_connection()
        conn.execute('DELETE FROM elections WHERE region = ? AND candidate = ?', (region, 'No Candidate Yet'))
        conn.execute('INSERT OR IGNORE INTO elections (region, candidate, votes) VALUES (?, ?, ?)', (region, candidate, 0))
        conn.commit(); conn.close()
    return redirect(url_for('admin_manage_candidates'))

@app.route('/admin/remove_candidate', methods=['POST'])
@admin_required
def admin_remove_candidate():
    region = request.form.get('region'); candidate = request.form.get('candidate')
    if region and candidate:
        conn = get_db_connection()
        conn.execute('DELETE FROM elections WHERE region = ? AND candidate = ?', (region, candidate))
        if not conn.execute('SELECT candidate FROM elections WHERE region = ?', (region,)).fetchone():
             conn.execute('INSERT INTO elections (region, candidate, votes) VALUES (?, ?, ?)', (region, 'No Candidate Yet', 0))
        conn.commit(); conn.close()
    return redirect(url_for('admin_manage_candidates'))

@app.route('/admin/manage_voters')
@admin_required
def admin_manage_voters():
    conn = get_db_connection()
    voters = conn.execute('SELECT username, region_assigned, has_voted FROM users WHERE role = "user"').fetchall()
    _, regions_list = get_election_config(conn)
    conn.close()
    return render_template_string(HTML_TEMPLATE, page='admin_voters', voters=voters, regions_list=regions_list)

@app.route('/admin/assign_region', methods=['POST'])
@admin_required
def admin_assign_region():
    username = request.form.get('voter_username'); region = request.form.get('assigned_region')
    if username and region:
        conn = get_db_connection()
        conn.execute('UPDATE users SET region_assigned = ? WHERE username = ? AND role = "user"', (region, username))
        conn.commit(); conn.close()
    return redirect(url_for('admin_manage_voters'))

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('home'))

# --- FRONTEND ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>ZKP Secure Voting</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f4f4f9; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); width: 800px; max-width: 90%; }
        h2 { color: #333; text-align: center; }
        input, select, button, .vote-card { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; }
        button { background: #4a90e2; color: white; cursor: pointer; border: none; font-weight: bold; }
        button:hover { background: #357abd; }
        .vote-card { padding: 15px; margin-bottom: 10px; border-radius: 8px; }
        .stat-row { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid #f0f0f0; }
        .alert { padding: 10px; background: #e8f4fd; color: #0d47a1; border-radius: 4px; font-size: 0.9em; margin-bottom: 15px; }
        .hidden { display: none; }
        .status-box { padding: 15px; border-radius: 8px; font-size: 1.1em; font-weight: bold; text-align: center; margin-bottom: 20px; }
        .status-active { background: #d4edda; color: #155724; border: 2px solid #c3e6cb; }
        .status-ended { background: #fff3cd; color: #856404; border: 2px solid #ffeeba; }
        .status-published { background: #d1ecf1; color: #0c5460; border: 2px solid #bee5eb; }
        .admin-nav-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }
        .nav-card { background: #f7f7f7; padding: 20px; border-radius: 8px; border: 1px solid #ddd; text-align: center; transition: all 0.2s; }
        .nav-card:hover { box-shadow: 0 4px 8px rgba(0,0,0,0.1); background: #eaf3ff; }
        .nav-card a { font-weight: bold; color: #4a90e2; text-decoration: none; display: block; margin-top: 10px; }
        .config-grid { display: flex; flex-wrap: wrap; gap: 20px; margin-top: 20px; }
        .form-group { flex: 1 1 100%; margin-bottom: 0; border: 1px solid #ccc; padding: 15px; border-radius: 8px; }
        .voter-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .voter-table th, .voter-table td { border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 0.9em; }
        .voter-table th { background-color: #f2f2f2; }
        .delete-btn { background: #e74c3c !important; }
        .end-btn { background: #f39c12 !important; }
        .publish-btn { background: #3498db !important; }
        .add-btn { background: #1abc9c !important; }
        .assign-btn { background: #4CAF50 !important; }
    </style>
</head>
<body>

<div class="container">
    {% if page == 'home' %}
        <h2>Secure ZKP Voting</h2>
        <p style="text-align:center; color: #666;">Authenticated by Schnorr Zero Knowledge Proofs.</p>
        <button onclick="window.location.href='/login_page'">Login (ZKP)</button>
        <button onclick="window.location.href='/register_page'" style="background: #2ecc71;">Register New User</button>
    
    {% elif page == 'register' %}
        <h2>Register</h2>
        <input type="text" id="reg_username" placeholder="Username">
        <input type="password" id="reg_password" placeholder="Password">
        <div id="status" class="alert hidden"></div>
        <button onclick="performRegistration()">Generate Keys & Register</button>
        <p style="font-size: 12px; color: #888;">Note: Normal users must be assigned a region by admin.</p>
        <a href="/">Back</a>

    {% elif page == 'login' %}
        <h2>ZKP Login</h2>
        <input type="text" id="login_username" placeholder="Username">
        <input type="password" id="login_password" placeholder="Password">
        <div id="status" class="alert hidden"></div>
        <button onclick="performZKPLogin()">Authenticate</button>
        <a href="/">Back</a>

    {% elif page == 'voting_dashboard' %}
        <h2>Voting Booth</h2>
        <p>Welcome, {{ user }}</p>
        {% if error_message %}
             <div class="alert" style="background:#f8d7da; color:#721c24;">{{ error_message }}</div>
             <button onclick="window.location.href='/logout'" style="background: #777;">Logout</button>
        {% elif has_voted %}
            <div class="alert" style="background:#d4edda; color:#155724;">Confirmed: Your vote has been recorded anonymously.</div>
            <button onclick="window.location.href='/logout'" style="background: #777;">Logout</button>
        {% else %}
            {% set assigned_region_name = assigned_region if assigned_region else 'N/A' %}
            <div class="alert">You are registered to vote only in the **{{ assigned_region_name }}** region.</div>
            <form action="/vote" method="POST">
                <input type="hidden" name="region" value="{{ assigned_region }}" required>
                <label>Candidates for **{{ assigned_region_name }}**:</label>
                <select name="candidate" id="candidateSelect">
                    <option value="">-- Select Candidate --</option>
                    {% for candidate in regions[assigned_region] %}
                        <option value="{{ candidate }}">{{ candidate }}</option>
                    {% endfor %}
                </select>
                <button type="submit">Cast Secure Vote</button>
            </form>
            <a href="/logout">Logout</a>
        {% endif %}

    {% elif page == 'final_results' %}
        <h2>Final Election Results</h2>
        <div class="status-box status-published">OFFICIAL RESULTS</div>
        <p>The results have been published by the Election Commission.</p>
        {% for region, result in final_results.items() %}
            <div class="vote-card" style="border: 2px solid #4a90e2;">
                <strong>{{ region }} Region Winner(s): {{ result.winners|join(' and ') }}</strong>
                <p style="font-size: 0.9em; margin-top: 5px; color: #777;">Winning Votes: {{ result.max_votes }}</p>
                {% for candidate_data in result.candidates %}
                    <div class="stat-row" {% if candidate_data.candidate in result.winners %}style="background: #e6f7ff; font-weight: bold;"{% endif %}>
                        <span>{{ candidate_data.candidate }}</span>
                        <span>{{ candidate_data.votes }} votes</span>
                    </div>
                {% endfor %}
            </div>
        {% endfor %}
        <button onclick="window.location.href='/logout'">Logout</button>

    {% elif page == 'admin_dashboard' %}
        <h2>Election Commission (Admin)</h2>
        <div class="alert" style="background: #fff3cd; color: #856404;">Status: **{{ election_status|upper }}**</div>
        <p><a href="/admin/manage" style="color: #4a90e2; font-weight: bold;">Go to Admin Configuration Hub</a></p>
        <h3>Live Vote Tally</h3>
        {% if votes %}
            {% for region, candidates in votes.items() %}
                <div class="vote-card">
                    <strong>{{ region }} Region</strong>
                    {% for candidate_data in candidates %}
                        <div class="stat-row">
                            <span>{{ candidate_data.candidate }}</span>
                            <span>{{ candidate_data.votes }} votes</span>
                        </div>
                    {% endfor %}
                </div>
            {% endfor %}
        {% else %}
            <div class="alert">No election data configured yet.</div>
        {% endif %}
        <button onclick="window.location.href='/logout'" style="background: #e74c3c;">Logout</button>

    {% elif page == 'admin_navigation' %}
        <h2>Admin Configuration Hub</h2>
        <p><a href="/dashboard">Back to Results</a> | <a href="/logout">Logout</a></p>
        {% if election_status == 'active' %}
            <div class="status-box status-active">✅ ELECTION STATUS: ACTIVE</div>
        {% elif election_status == 'ended' %}
            <div class="status-box status-ended">⏳ ELECTION STATUS: ENDED (Results Hidden)</div>
        {% else %}
            <div class="status-box status-published">📢 ELECTION STATUS: PUBLISHED</div>
        {% endif %}
        <div class="form-group" style="padding: 20px;">
            <h3>Election Controls</h3>
            <div style="display: flex; gap: 10px;">
                {% if election_status == 'active' %}
                    <form action="/admin/change_status" method="POST" style="flex:1;">
                        <button type="submit" class="end-btn" name="action" value="end">STOP VOTING (Hold Results)</button>
                    </form>
                {% elif election_status == 'ended' %}
                    <form action="/admin/change_status" method="POST" style="flex:1;">
                        <button type="submit" class="publish-btn" name="action" value="publish">PUBLISH FINAL RESULTS</button>
                    </form>
                     <form action="/admin/change_status" method="POST" style="flex:1;">
                        <button type="submit" class="assign-btn" name="action" value="start_new" onclick="return confirm('Start fresh? This deletes all votes.');">RESTART ELECTION</button>
                    </form>
                {% else %}
                    <form action="/admin/change_status" method="POST" style="flex:1;">
                        <button type="submit" class="assign-btn" name="action" value="start_new" onclick="return confirm('Start fresh? This deletes all votes.');">START NEW ELECTION</button>
                    </form>
                {% endif %}
            </div>
        </div>
        <h3>Configuration Links</h3>
        <div class="admin-nav-grid">
            <div class="nav-card"><h4>Region Setup</h4><a href="/admin/manage_regions">Manage Regions</a></div>
            <div class="nav-card"><h4>Candidate Setup</h4><a href="/admin/manage_candidates">Manage Candidates</a></div>
            <div class="nav-card"><h4>Voter Assignment</h4><a href="/admin/manage_voters">Manage Voters</a></div>
        </div>

    {% elif page == 'admin_regions' %}
        <h2>Region Management</h2>
        <p><a href="/admin/manage">Back to Admin Hub</a> | <a href="/logout">Logout</a></p>
        <div class="config-grid">
            <div class="form-group">
                <h3>Add New Region</h3>
                <form action="/admin/add_region" method="POST">
                    <input type="text" name="region_name" placeholder="Region Name" required>
                    <button type="submit" class="add-btn">Add Region</button>
                </form>
            </div>
            <div class="form-group">
                <h3>Remove Region</h3>
                <form action="/admin/remove_region" method="POST">
                    <select name="region" required>{% for region in regions_list %}<option value="{{ region }}">{{ region }}</option>{% endfor %}</select>
                    <button type="submit" class="delete-btn">Remove Region</button>
                </form>
            </div>
        </div>

    {% elif page == 'admin_candidates' %}
        <h2>Candidate Management</h2>
        <p><a href="/admin/manage">Back to Admin Hub</a> | <a href="/logout">Logout</a></p>
        <div class="config-grid">
            <div class="form-group">
                <h3>Add Candidate</h3>
                <form action="/admin/add_candidate" method="POST">
                    <select name="region" required>{% for region in regions_list %}<option value="{{ region }}">{{ region }}</option>{% endfor %}</select>
                    <input type="text" name="candidate_name" placeholder="Name" required>
                    <button type="submit" class="end-btn">Add Candidate</button>
                </form>
            </div>
            <div class="form-group">
                <h3>Remove Candidate</h3>
                <form action="/admin/remove_candidate" method="POST">
                    <select name="region" id="removeRegionSelect"><option value="">-- Select Region --</option>
                        {% for region in regions_list %}<option value="{{ region }}">{{ region }}</option>{% endfor %}
                    </select>
                    <select name="candidate" id="removeCandidateSelect"><option value="">-- Select Candidate --</option></select>
                    <button type="submit" class="delete-btn">Remove Candidate</button>
                </form>
            </div>
        </div>

    {% elif page == 'admin_voters' %}
        <h2>Voter Region Assignment</h2>
        <p><a href="/admin/manage">Back to Admin Hub</a> | <a href="/logout">Logout</a></p>
        <div class="form-group">
            <h3>Assign Region</h3>
            <form action="/admin/assign_region" method="POST">
                <select name="voter_username" required>
                    <option value="">-- Select User --</option>
                    {% for voter in voters %}<option value="{{ voter.username }}">{{ voter.username }} ({{ 'VOTED' if voter.has_voted else 'Ready' }})</option>{% endfor %}
                </select>
                <select name="assigned_region" required>
                    {% for region in regions_list %}<option value="{{ region }}">{{ region }}</option>{% endfor %}
                </select>
                <button type="submit" class="assign-btn">Assign Region</button>
            </form>
            <table class="voter-table">
                <thead><tr><th>Username</th><th>Assigned Region</th><th>Voted?</th></tr></thead>
                <tbody>{% for voter in voters %}<tr><td>{{ voter.username }}</td><td>{{ voter.region_assigned if voter.region_assigned else 'UNASSIGNED' }}</td><td>{{ 'YES' if voter.has_voted else 'NO' }}</td></tr>{% endfor %}</tbody>
            </table>
        </div>
    {% endif %}
</div>

<script>
    const P = BigInt({{ p }});
    const G = BigInt({{ g }});
    const regionConfig = {{ regions_config|default({})|tojson|safe }}; 

    function modPow(base, exp, mod) {
        let res = 1n;
        base = base % mod;
        while (exp > 0n) {
            if (exp % 2n === 1n) res = (res * base) % mod;
            base = (base * base) % mod;
            exp = exp / 2n;
        }
        return res;
    }

    async function stringToPrivateKey(str) {
        const msgBuffer = new TextEncoder().encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return BigInt('0x' + hashHex) % (P - 1n);
    }

    async function performRegistration() {
        const user = document.getElementById('reg_username').value;
        const pass = document.getElementById('reg_password').value;
        if (!user || !pass) { alert('Fill out all fields.'); return; }
        const x = await stringToPrivateKey(pass);
        const y = modPow(G, x, P); 
        fetch('/api/register', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username: user, y: y.toString() })
        }).then(res => res.json()).then(data => {
            if(data.status === 'success') {
                alert('Registration successful! Admin must assign your voting region before you can vote.');
                window.location.href = '/login_page';
            } else { alert('Error: ' + data.message); }
        });
    }

    async function performZKPLogin() {
        const user = document.getElementById('login_username').value;
        const pass = document.getElementById('login_password').value;
        if (!user || !pass) { alert('Fill out all fields.'); return; }
        const x = await stringToPrivateKey(pass); 
        const r = BigInt(Math.floor(Math.random() * 100000)); 
        const t = modPow(G, r, P); 
        fetch('/api/login/step1', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username: user, t: t.toString() })
        }).then(res => res.json()).then(data => {
            if(data.status !== 'continue') { alert(data.message); return; }
            const c = BigInt(data.c); 
            const s = r + (c * x);
            return fetch('/api/login/step2', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ username: user, s: s.toString() })
            });
        }).then(res => res.json()).then(data => {
            if(data.status === 'success') { window.location.href = data.redirect; } 
            else { 
                const statusDiv = document.getElementById('status');
                statusDiv.innerText = data.message;
                statusDiv.classList.remove('hidden');
                statusDiv.style.background = '#f8d7da'; statusDiv.style.color = '#721c24';
            }
        });
    }

    function updateCandidatesForRemoval(config) {
        const regionSelect = document.getElementById('removeRegionSelect');
        const candidateSelect = document.getElementById('removeCandidateSelect');
        if (!regionSelect || !candidateSelect) return;
        const selectedRegion = regionSelect.value;
        candidateSelect.innerHTML = '<option value="">-- Select Candidate --</option>';
        if (selectedRegion && config[selectedRegion]) {
            config[selectedRegion].forEach(candidate => {
                const option = document.createElement('option');
                option.value = candidate; option.text = candidate;
                candidateSelect.appendChild(option);
            });
        }
    }
    
    document.addEventListener('DOMContentLoaded', () => {
        const regionSelect = document.getElementById('removeRegionSelect');
        if (regionSelect) {
            regionSelect.onchange = () => { updateCandidatesForRemoval(regionConfig); };
             updateCandidatesForRemoval(regionConfig);
        }
    });
</script>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(debug=True, port=5000)