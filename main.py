
import hashlib
import secrets
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
app.secret_key = "your_secret_key"

LOG_FILE = 'admin_log.txt'

def load_data():
    try:
        with open("data.json") as f:
            return json.load(f)
    except Exception:
        return {
            "users": {},
            "players": {},
            "teams": {},
            "matches": [],
            "banned_users": {},
            "settings": {
                "forum_enabled": True,
                "hide_elo": False,
                "hide_records": False,
                "registration_enabled": True,
                "require_approval": False
            },
            "feature_toggles": {},
            "site_content": {},
            "forum_posts": [],
            "stories": [],
            "rubrics": {}
        }

def save_data(data):
    with open("data.json", "w") as f:
        json.dump(data, f, indent=2)

def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{hashed}"

def verify_password(password, stored_hash):
    try:
        salt, hashed = stored_hash.split(':')
        return hashlib.sha256((password + salt).encode()).hexdigest() == hashed
    except:
        return False

def requires_admin():
    user = get_current_user()
    return user and user.get("is_admin", False)

def requires_login():
    return bool(session.get('user_id'))

def is_banned(user_id):
    data = load_data()
    ban_info = data['banned_users'].get(user_id)
    if not ban_info:
        return False
    ban_until = datetime.fromisoformat(ban_info['until'])
    return datetime.now() < ban_until

def get_current_user():
    if not session.get('user_id'):
        return None
    data = load_data()
    return data['users'].get(session['user_id'])

def log_admin_action(action, admin_username):
    with open(LOG_FILE, 'a') as f:
        timestamp = datetime.now().isoformat()
        f.write(f"[{timestamp}] {admin_username}: {action}\n")

def calculate_expected_score(elo1, elo2):
    power = (elo2 - elo1) / 400
    expected = 1 / (1 + (10 ** power))
    return expected

def update_elo_ratings(winner_elo, loser_elo, k=32):
    expected_winner = calculate_expected_score(winner_elo, loser_elo)
    expected_loser = calculate_expected_score(loser_elo, winner_elo)
    new_winner_elo = int(round(winner_elo + k * (1 - expected_winner)))
    new_loser_elo = int(round(loser_elo + k * (0 - expected_loser)))
    return new_winner_elo, new_loser_elo

@app.route('/')
def index():
    data = load_data()
    return render_template('index.html',
        is_admin=requires_admin(),
        is_logged_in=requires_login(),
        current_user=get_current_user(),
        site_content=data.get('site_content', {})
    )

@app.route('/register', methods=['GET', 'POST', 'HEAD'])
def register():
    data = load_data()
    if not data['settings'].get('registration_enabled', True):
        flash('Registration is currently disabled.', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        player_name = request.form['player_name'].strip()
        if not all([username, email, password, player_name]):
            flash('All fields are required!', 'error')
            return render_template('register.html')
        for user_data in data['users'].values():
            if user_data['username'] == username:
                flash('Username already exists!', 'error')
                return render_template('register.html')
        if player_name not in data['players']:
            flash('Player name not found! Please contact admin to add you as a debater first.', 'error')
            return render_template('register.html')
        user_id = secrets.token_hex(16)
        data['users'][user_id] = {
            'username': username,
            'email': email,
            'password': hash_password(password),
            'player_name': player_name,
            'is_admin': False,
            'created_date': datetime.now().isoformat(),
            'approved': not data['settings'].get('require_approval', False)
        }
        save_data(data)
        if data['settings'].get('require_approval', False):
            flash('Account created! Please wait for admin approval.', 'success')
        else:
            session['user_id'] = user_id
            flash('Account created successfully!', 'success')
            return redirect(url_for('index'))
    return render_template('register.html', players=load_data()['players'])

@app.route('/login', methods=['GET', 'POST', 'HEAD'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        data = load_data()
        user_id = None
        for uid, user_data in data['users'].items():
            if user_data['username'] == username:
                user_id = uid
                break
        if user_id and verify_password(password, data['users'][user_id]['password']):
            if not data['users'][user_id].get('approved', True):
                flash('Account pending approval!', 'error')
                return render_template('login.html')
            if is_banned(user_id):
                ban_info = data['banned_users'][user_id]
                flash(f'You are banned until {ban_info["until"][:19]}. Reason: {ban_info["reason"]}', 'error')
                return render_template('login.html')
            session['user_id'] = user_id
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/my_account', methods=['GET', 'HEAD'])
def my_account():
    if not requires_login():
        flash('Please log in to view your account.', 'error')
        return redirect(url_for('login'))
    user = get_current_user()
    data = load_data()
    player_name = user.get('player_name')
    player_data = data['players'].get(player_name, {})
    return render_template('my_account.html',
        user=user,
        player=player_data,
        is_admin=requires_admin(),
        is_logged_in=True,
        current_user=user,
        site_content=data['site_content']
    )

@app.route('/user_management', methods=['GET', 'HEAD'])
def user_management():
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    data = load_data()
    return render_template('user_management.html',
        users=data['users'],
        banned_users=data['banned_users'],
        is_admin=requires_admin(),
        is_logged_in=requires_login(),
        current_user=get_current_user()
    )

@app.route('/admin/change_password/<user_id>', methods=['POST'])
def admin_change_password(user_id):
    if not requires_admin():
        return "Unauthorized", 403
    data = load_data()
    user = data['users'].get(user_id)
    if not user:
        return "User not found", 404
    new_password = secrets.token_urlsafe(8)
    user['password'] = hash_password(new_password)
    save_data(data)
    with open('admin_log.txt', 'a') as log_file:
        log_file.write(f"[{datetime.now().isoformat()}] Admin {session['user_id']} reset password for user {user_id}\n")
    flash(f"New password for {user['username']}: {new_password}", 'success')
    return redirect(url_for('user_management'))

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if not requires_admin():
        return "Unauthorized", 403
    data = load_data()
    user = data['users'].get(user_id)
    if not user:
        return "User not found", 404
    deleted_username = user['username']
    del data['users'][user_id]
    save_data(data)
    with open('admin_log.txt', 'a') as log_file:
        log_file.write(f"[{datetime.now().isoformat()}] Admin {session['user_id']} deleted user {user_id} ({deleted_username})\n")
    flash(f"Deleted user: {deleted_username}", 'success')
    return redirect(url_for('user_management'))

@app.route('/make_admin/<user_id>', methods=['POST'])
def make_admin(user_id):
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    data = load_data()
    if user_id in data['users']:
        data['users'][user_id]['is_admin'] = True
        save_data(data)
        flash('Team leader powers granted.', 'success')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('user_management'))

@app.route('/remove_admin/<user_id>', methods=['POST'])
def remove_admin(user_id):
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    data = load_data()
    if user_id in data['users']:
        data['users'][user_id]['is_admin'] = False
        save_data(data)
        flash('Admin privileges removed!', 'success')
    return redirect(url_for('user_management'))

@app.route('/ban_user', methods=['POST'])
def ban_user():
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    user_id = request.form['user_id']
    ban_days = int(request.form['ban_days'])
    reason = request.form['reason'].strip()
    data = load_data()
    ban_until = datetime.now() + timedelta(days=ban_days)
    data['banned_users'][user_id] = {
        'until': ban_until.isoformat(),
        'reason': reason,
        'banned_by': session['user_id'],
        'banned_date': datetime.now().isoformat()
    }
    save_data(data)
    flash('User banned successfully!', 'success')
    return redirect(url_for('user_management'))

@app.route('/unban_user/<user_id>', methods=['POST'])
def unban_user(user_id):
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    data = load_data()
    if user_id in data['banned_users']:
        del data['banned_users'][user_id]
        save_data(data)
        flash('User unbanned!', 'success')
    return redirect(url_for('user_management'))

@app.route('/admin_settings', methods=['GET', 'POST', 'HEAD'])
def admin_settings():
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    data = load_data()
    if request.method == 'POST':
        toggles = [
            'match_history_visible',
            'player_profiles_enabled',
            'team_stats_enabled',
            'fun_facts_enabled',
            'achievements_enabled'
        ]
        if 'feature_toggles' not in data:
            data['feature_toggles'] = {}
        for toggle in toggles:
            data['feature_toggles'][toggle] = toggle in request.form
        data['settings']['forum_enabled'] = 'forum_enabled' in request.form
        data['settings']['hide_elo'] = 'hide_elo' in request.form
        data['settings']['hide_records'] = 'hide_records' in request.form
        data['settings']['registration_enabled'] = 'registration_enabled' in request.form
        data['settings']['require_approval'] = 'require_approval' in request.form
        save_data(data)
        flash('Settings updated!', 'success')
        return redirect(url_for('admin_settings'))
    return render_template('admin_settings.html', data=data)

@app.route('/create_match_layout', methods=['GET', 'POST'])
def create_match_layout_route():
    data = load_data()
    matches = []
    format = None

    if request.method == 'POST':
        format = request.form.get('format')
        present_participants = request.form.getlist('present_participants')
        potential_judges = request.form.getlist('potential_judges')
        if format == 'LD':
            eligible_players = [name for name in present_participants if name in data['players'] and 'LD' in data['players'][name].get('formats', [])]
            sorted_players = sorted(eligible_players, key=lambda name: data['players'][name]['elo'], reverse=True)
            for i in range(0, len(sorted_players) - 1, 2):
                p1 = sorted_players[i]
                p2 = sorted_players[i+1]
                match = {
                    'participant1': (p1, data['players'][p1]),
                    'participant2': (p2, data['players'][p2]),
                    'elo_diff': abs(data['players'][p1]['elo'] - data['players'][p2]['elo']),
                    'judge': potential_judges[:1] if potential_judges else [],
                }
                matches.append(match)
        elif format == 'PF':
            eligible_teams = [name for name in present_participants if name in data['teams'] and data['teams'][name].get('format') == 'PF']
            sorted_teams = sorted(eligible_teams, key=lambda name: data['teams'][name]['elo'], reverse=True)
            for i in range(0, len(sorted_teams) - 1, 2):
                t1 = sorted_teams[i]
                t2 = sorted_teams[i+1]
                match = {
                    'participant1': (t1, data['teams'][t1]),
                    'participant2': (t2, data['teams'][t2]),
                    'elo_diff': abs(data['teams'][t1]['elo'] - data['teams'][t2]['elo']),
                    'judge': potential_judges[:1] if potential_judges else [],
                }
                matches.append(match)
        return render_template(
            'match_layout_result.html',
            matches=matches,
            format=format,
            is_admin=requires_admin(),
            is_logged_in=requires_login(),
            current_user=get_current_user()
        )
    return render_template(
        'create_match_layout.html',
        players=data['players'],
        teams=data['teams'],
        is_admin=requires_admin(),
        is_logged_in=requires_login(),
        current_user=get_current_user()
    )

# ... (include all your other routes, such as player_profile, add_team, stories, rubrics, record_match, etc. from your original main.py!)

if __name__ == '__main__':
    data = load_data()
    if not data['users']:
        admin_id = secrets.token_hex(16)
        data['users'][admin_id] = {
            'username': 'admin',
            'email': 'admin@school.edu',
            'password': hash_password('admin123'),
            'player_name': 'Administrator',
            'is_admin': True,
            'created_date': datetime.now().isoformat(),
            'approved': True
        }
        save_data(data)
        print("Default admin account created: username='admin', password='admin123'")
    app.run(host='0.0.0.0', port=5000, debug=True)
