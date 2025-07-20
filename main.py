
from flask import Flask, render_template, request, redirect, url_for, flash, session
import json
import os
from datetime import datetime, timedelta
import hashlib
import secrets

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'

# File to store all data
DATA_FILE = 'debate_data.json'

def load_data():
    """Load all data from JSON file"""
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {
        'players': {},
        'teams': {},
        'matches': [],
        'stories': [],
        'rubrics': {},
        'users': {},
        'forum_posts': [],
        'banned_users': {},
        'site_content': {
            'title': 'Capital High School Debate System',
            'welcome_message': 'Welcome to our debate community!',
            'pf_description': 'Team-based debate format (2v2)',
            'ld_description': 'Individual debate format (1v1)',
            'theme_color': '#3498db'
        },
        'settings': {
            'forum_enabled': True,
            'hide_elo': False,
            'hide_records': False,
            'registration_enabled': True,
            'require_approval': False
        }
    }

def save_data(data):
    """Save all data to JSON file"""
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def hash_password(password):
    """Hash password with salt"""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{hashed}"

def verify_password(password, stored_hash):
    """Verify password against stored hash"""
    try:
        salt, hashed = stored_hash.split(':')
        return hashlib.sha256((password + salt).encode()).hexdigest() == hashed
    except:
        return False

def calculate_expected_score(elo1, elo2):
    """Calculate expected score using Elo formula"""
    power = (elo2 - elo1) / 400
    expected = 1 / (1 + (10 ** power))
    return expected

def update_elo_ratings(winner_elo, loser_elo, k_factor=32):
    """Update Elo ratings and return new ratings"""
    winner_expected = calculate_expected_score(winner_elo, loser_elo)
    loser_expected = calculate_expected_score(loser_elo, winner_elo)
    
    new_winner_elo = round(winner_elo + k_factor * (1 - winner_expected))
    new_loser_elo = round(loser_elo + k_factor * (0 - loser_expected))
    
    return new_winner_elo, new_loser_elo

def requires_admin():
    """Check if user is admin"""
    if not session.get('user_id'):
        return False
    data = load_data()
    user_id = session.get('user_id')
    return data['users'].get(user_id, {}).get('is_admin', False)

def requires_login():
    """Check if user is logged in"""
    return session.get('user_id') is not None

def is_banned(user_id):
    """Check if user is banned"""
    data = load_data()
    ban_info = data['banned_users'].get(user_id)
    if not ban_info:
        return False
    
    ban_until = datetime.fromisoformat(ban_info['until'])
    return datetime.now() < ban_until

def get_current_user():
    """Get current user data"""
    if not session.get('user_id'):
        return None
    data = load_data()
    return data['users'].get(session['user_id'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
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
        
        # Check if username exists
        for user_data in data['users'].values():
            if user_data['username'] == username:
                flash('Username already exists!', 'error')
                return render_template('register.html')
        
        # Check if player exists
        if player_name not in data['players']:
            flash('Player name not found! Please contact admin to add you as a debater first.', 'error')
            return render_template('register.html')
        
        # Create user account
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        data = load_data()
        
        # Find user by username
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
    """User logout"""
    session.pop('user_id', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/')
def index():
    """Main homepage"""
    data = load_data()
    return render_template('homepage.html', 
                         is_admin=requires_admin(), 
                         is_logged_in=requires_login(),
                         current_user=get_current_user(),
                         settings=data['settings'],
                         site_content=data['site_content'])

@app.route('/public-forum')
def public_forum():
    """Public Forum homepage"""
    data = load_data()
    teams = data['teams']
    
    pf_teams = {k: v for k, v in teams.items() if v.get('format') == 'PF'}
    sorted_teams = sorted(pf_teams.items(), key=lambda x: x[1]['elo'], reverse=True)
    
    return render_template('public_forum.html', 
                         teams=sorted_teams, 
                         is_admin=requires_admin(),
                         is_logged_in=requires_login(),
                         current_user=get_current_user(),
                         site_content=data['site_content'])

@app.route('/lincoln-douglas')
def lincoln_douglas():
    """Lincoln-Douglas homepage"""
    data = load_data()
    players = data['players']
    
    ld_players = {k: v for k, v in players.items() if 'LD' in v.get('formats', []) or v.get('format') == 'LD'}
    sorted_players = sorted(ld_players.items(), key=lambda x: x[1]['elo'], reverse=True)
    
    return render_template('lincoln_douglas.html', 
                         players=sorted_players, 
                         is_admin=requires_admin(),
                         is_logged_in=requires_login(),
                         current_user=get_current_user(),
                         site_content=data['site_content'])

@app.route('/add_player', methods=['GET', 'POST'])
def add_player():
    """Add a new player - Admin only"""
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name'].strip()
        debate_formats = request.form.getlist('formats')
        
        if not name or not debate_formats:
            flash('Name and at least one format are required!', 'error')
            return render_template('add_player.html')
        
        data = load_data()
        
        if name in data['players']:
            existing_formats = data['players'][name].get('formats', [data['players'][name].get('format', [])])
            for fmt in debate_formats:
                if fmt not in existing_formats:
                    existing_formats.append(fmt)
            data['players'][name]['formats'] = existing_formats
            flash(f'Updated {name} formats!', 'success')
        else:
            player_data = {
                'formats': debate_formats,
                'elo': 1200,
                'matches_won': 0,
                'matches_lost': 0,
                'total_matches': 0,
                'joined_date': datetime.now().isoformat()
            }
            data['players'][name] = player_data
            flash(f'Added {name}!', 'success')
        
        save_data(data)
        return redirect(url_for('index'))
    
    return render_template('add_player.html')

@app.route('/forum')
def forum():
    """Discussion forum"""
    data = load_data()
    
    if not data['settings'].get('forum_enabled', False):
        flash('Forum is currently disabled.', 'error')
        return redirect(url_for('index'))
    
    posts = []
    for post in data['forum_posts']:
        # Get author info
        author_info = data['users'].get(post['author_id'], {})
        post['author_name'] = author_info.get('username', 'Unknown User')
        posts.append(post)
    
    posts.sort(key=lambda x: x['date'], reverse=True)
    
    return render_template('forum.html', 
                         posts=posts, 
                         is_admin=requires_admin(),
                         is_logged_in=requires_login(),
                         current_user=get_current_user())

@app.route('/add_forum_post', methods=['GET', 'POST'])
def add_forum_post():
    """Add a forum post"""
    if not requires_login():
        flash('Please log in to post!', 'error')
        return redirect(url_for('login'))
    
    data = load_data()
    
    if not data['settings'].get('forum_enabled', False):
        flash('Forum is currently disabled.', 'error')
        return redirect(url_for('index'))
    
    user_id = session['user_id']
    if is_banned(user_id):
        flash('You are currently banned from posting.', 'error')
        return redirect(url_for('forum'))
    
    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        
        if not title or not content:
            flash('Title and content are required!', 'error')
            return render_template('add_forum_post.html')
        
        post = {
            'id': len(data['forum_posts']) + 1,
            'title': title,
            'content': content,
            'author_id': user_id,
            'date': datetime.now().isoformat(),
            'replies': []
        }
        
        data['forum_posts'].append(post)
        save_data(data)
        flash('Post added successfully!', 'success')
        return redirect(url_for('forum'))
    
    return render_template('add_forum_post.html')

@app.route('/moderate_forum')
def moderate_forum():
    """Forum moderation panel - Admin only"""
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    
    data = load_data()
    
    # Get all posts with author info
    posts = []
    for post in data['forum_posts']:
        author_info = data['users'].get(post['author_id'], {})
        post['author_name'] = author_info.get('username', 'Unknown User')
        posts.append(post)
    
    return render_template('moderate_forum.html', 
                         posts=posts, 
                         banned_users=data['banned_users'],
                         users=data['users'])

@app.route('/delete_post/<int:post_id>')
def delete_post(post_id):
    """Delete a forum post - Admin only"""
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    
    data = load_data()
    data['forum_posts'] = [p for p in data['forum_posts'] if p['id'] != post_id]
    save_data(data)
    flash('Post deleted!', 'success')
    return redirect(url_for('moderate_forum'))

@app.route('/ban_user', methods=['POST'])
def ban_user():
    """Ban a user - Admin only"""
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
    return redirect(url_for('moderate_forum'))

@app.route('/unban_user/<user_id>')
def unban_user(user_id):
    """Unban a user - Admin only"""
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    
    data = load_data()
    if user_id in data['banned_users']:
        del data['banned_users'][user_id]
        save_data(data)
        flash('User unbanned!', 'success')
    
    return redirect(url_for('moderate_forum'))

@app.route('/admin_panel')
def admin_panel():
    """Main admin panel"""
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    
    data = load_data()
    
    # Get pending user approvals
    pending_users = {uid: user for uid, user in data['users'].items() 
                    if not user.get('approved', True)}
    
    return render_template('admin_panel.html', 
                         data=data, 
                         pending_users=pending_users)

@app.route('/approve_user/<user_id>')
def approve_user(user_id):
    """Approve a user - Admin only"""
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    
    data = load_data()
    if user_id in data['users']:
        data['users'][user_id]['approved'] = True
        save_data(data)
        flash('User approved!', 'success')
    
    return redirect(url_for('admin_panel'))

@app.route('/make_admin/<user_id>')
def make_admin(user_id):
    """Grant admin privileges - Admin only"""
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    
    data = load_data()
    if user_id in data['users']:
        data['users'][user_id]['is_admin'] = True
        save_data(data)
        flash('User granted admin privileges!', 'success')
    
    return redirect(url_for('admin_panel'))

@app.route('/remove_admin/<user_id>')
def remove_admin(user_id):
    """Remove admin privileges - Admin only"""
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    
    data = load_data()
    if user_id in data['users']:
        data['users'][user_id]['is_admin'] = False
        save_data(data)
        flash('Admin privileges removed!', 'success')
    
    return redirect(url_for('admin_panel'))

@app.route('/site_editor', methods=['GET', 'POST'])
def site_editor():
    """Website content editor - Admin only"""
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    
    data = load_data()
    
    if request.method == 'POST':
        data['site_content']['title'] = request.form['title']
        data['site_content']['welcome_message'] = request.form['welcome_message']
        data['site_content']['pf_description'] = request.form['pf_description']
        data['site_content']['ld_description'] = request.form['ld_description']
        data['site_content']['theme_color'] = request.form['theme_color']
        
        save_data(data)
        flash('Site content updated!', 'success')
        return redirect(url_for('site_editor'))
    
    return render_template('site_editor.html', site_content=data['site_content'])

@app.route('/admin_settings', methods=['GET', 'POST'])
def admin_settings():
    """Admin settings - Admin only"""
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    
    data = load_data()
    
    if request.method == 'POST':
        data['settings']['forum_enabled'] = 'forum_enabled' in request.form
        data['settings']['hide_elo'] = 'hide_elo' in request.form
        data['settings']['hide_records'] = 'hide_records' in request.form
        data['settings']['registration_enabled'] = 'registration_enabled' in request.form
        data['settings']['require_approval'] = 'require_approval' in request.form
        
        save_data(data)
        flash('Settings updated!', 'success')
        return redirect(url_for('admin_settings'))
    
    return render_template('admin_settings.html', settings=data['settings'])

# Continue with existing routes...
@app.route('/create_team', methods=['GET', 'POST'])
def create_team():
    """Create a new PF team - Admin only"""
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    
    data = load_data()
    pf_players = {k: v for k, v in data['players'].items() 
                  if 'PF' in v.get('formats', []) or v.get('format') == 'PF'}
    
    if request.method == 'POST':
        team_name = request.form['team_name'].strip()
        member1 = request.form['member1']
        member2 = request.form['member2']
        
        if not team_name or member1 == member2:
            flash('Invalid team configuration!', 'error')
            return render_template('create_team.html', players=pf_players)
        
        if team_name in data['teams']:
            flash('Team name already exists!', 'error')
            return render_template('create_team.html', players=pf_players)
        
        avg_elo = round((data['players'][member1]['elo'] + data['players'][member2]['elo']) / 2)
        
        data['teams'][team_name] = {
            'members': [member1, member2],
            'elo': avg_elo,
            'format': 'PF',
            'matches_won': 0,
            'matches_lost': 0,
            'total_matches': 0,
            'created_date': datetime.now().isoformat()
        }
        save_data(data)
        flash(f'Created team {team_name}!', 'success')
        return redirect(url_for('public_forum'))
    
    return render_template('create_team.html', players=pf_players)

@app.route('/record_match', methods=['GET', 'POST'])
def record_match():
    """Record a match result - Admin only"""
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    
    data = load_data()
    
    if request.method == 'POST':
        match_type = request.form['match_type']
        
        if match_type == 'LD':
            winner = request.form['winner']
            loser = request.form['loser']
            
            if winner == loser:
                flash('A player cannot compete against themselves!', 'error')
                return render_template('record_match.html', data=data)
            
            winner_old_elo = data['players'][winner]['elo']
            loser_old_elo = data['players'][loser]['elo']
            
            new_winner_elo, new_loser_elo = update_elo_ratings(winner_old_elo, loser_old_elo)
            
            data['players'][winner]['elo'] = new_winner_elo
            data['players'][loser]['elo'] = new_loser_elo
            data['players'][winner]['matches_won'] += 1
            data['players'][loser]['matches_lost'] += 1
            data['players'][winner]['total_matches'] += 1
            data['players'][loser]['total_matches'] += 1
            
            match_record = {
                'type': 'LD',
                'winner': winner,
                'loser': loser,
                'participants': [winner, loser],
                'winner_elo_change': new_winner_elo - winner_old_elo,
                'loser_elo_change': new_loser_elo - loser_old_elo,
                'date': datetime.now().isoformat()
            }
            
        else:  # PF
            winning_team = request.form['winning_team']
            losing_team = request.form['losing_team']
            
            if winning_team == losing_team:
                flash('A team cannot compete against itself!', 'error')
                return render_template('record_match.html', data=data)
            
            winner_old_elo = data['teams'][winning_team]['elo']
            loser_old_elo = data['teams'][losing_team]['elo']
            
            new_winner_elo, new_loser_elo = update_elo_ratings(winner_old_elo, loser_old_elo)
            
            data['teams'][winning_team]['elo'] = new_winner_elo
            data['teams'][losing_team]['elo'] = new_loser_elo
            data['teams'][winning_team]['matches_won'] += 1
            data['teams'][losing_team]['matches_lost'] += 1
            data['teams'][winning_team]['total_matches'] += 1
            data['teams'][losing_team]['total_matches'] += 1
            
            for member in data['teams'][winning_team]['members']:
                data['players'][member]['matches_won'] += 1
                data['players'][member]['total_matches'] += 1
            
            for member in data['teams'][losing_team]['members']:
                data['players'][member]['matches_lost'] += 1
                data['players'][member]['total_matches'] += 1
            
            match_record = {
                'type': 'PF',
                'winning_team': winning_team,
                'losing_team': losing_team,
                'participants': data['teams'][winning_team]['members'] + data['teams'][losing_team]['members'],
                'winner_elo_change': new_winner_elo - winner_old_elo,
                'loser_elo_change': new_loser_elo - loser_old_elo,
                'date': datetime.now().isoformat()
            }
        
        data['matches'].append(match_record)
        save_data(data)
        flash('Match recorded successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('record_match.html', data=data)

@app.route('/stories')
def stories():
    """View all stories"""
    data = load_data()
    sorted_stories = sorted(data['stories'], key=lambda x: x['date'], reverse=True)
    return render_template('stories.html', 
                         stories=sorted_stories, 
                         is_admin=requires_admin(),
                         is_logged_in=requires_login(),
                         current_user=get_current_user())

@app.route('/add_story', methods=['GET', 'POST'])
def add_story():
    """Add a new story - Admin only"""
    if not requires_admin():
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        
        if not title or not content:
            flash('Title and content are required!', 'error')
            return render_template('add_story.html')
        
        data = load_data()
        story = {
            'id': len(data['stories']) + 1,
            'title': title,
            'content': content,
            'date': datetime.now().isoformat(),
            'author': get_current_user()['username']
        }
        
        data['stories'].append(story)
        save_data(data)
        flash('Story posted successfully!', 'success')
        return redirect(url_for('stories'))
    
    return render_template('add_story.html')

if __name__ == '__main__':
    # Create default admin account if no users exist
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
