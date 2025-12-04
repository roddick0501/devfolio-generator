from flask import Flask, render_template, request, redirect, url_for, send_file, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from bson.objectid import ObjectId
import io
import base64
import qrcode
import os
import requests
import traceback
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

# --- APP SETUP ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'b42907f1d8325fda2d3fcd6917c2f910437602425099d321c9dab187b04d89a5y')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# --- MONGODB SETUP ---
MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGODB_URI)
db = client['devfolio']  # Database name

# Collections
users_collection = db['users']
portfolios_collection = db['portfolios']

# Create indexes for better performance
users_collection.create_index('username', unique=True)
users_collection.create_index('email', unique=True, sparse=True)
portfolios_collection.create_index('user_id')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')

# --- USER CLASS FOR FLASK-LOGIN ---
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data.get('email')
        self.password = user_data.get('password')
        self.auth_provider = user_data.get('auth_provider', 'local')
        self.auth_id = user_data.get('auth_id')

@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None

# Health check endpoint
@app.route('/health')
def health_check():
    try:
        # Ping MongoDB
        client.admin.command('ping')
        return 'OK', 200
    except Exception as e:
        return f'Database error: {str(e)}', 500

# Error handling
@app.errorhandler(500)
def internal_error(error):
    return f"""
    <h1>500 Internal Server Error</h1>
    <pre>{traceback.format_exc()}</pre>
    """, 500

# --- AUTH ROUTES ---

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            
            # Check if username exists
            if users_collection.find_one({'username': username}):
                flash('Username taken')
                return redirect(url_for('register'))
            
            # Create new user
            user_data = {
                'username': username,
                'password': generate_password_hash(password, method='pbkdf2:sha256'),
                'auth_provider': 'local',
                'created_at': datetime.utcnow()
            }
            
            result = users_collection.insert_one(user_data)
            user_data['_id'] = result.inserted_id
            
            login_user(User(user_data))
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f'Registration error: {str(e)}')
            return redirect(url_for('register'))
    
    return render_template('auth.html', mode='register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = users_collection.find_one({'username': username})
        
        if user_data and user_data.get('auth_provider') == 'local' and check_password_hash(user_data.get('password', ''), password):
            login_user(User(user_data))
            return redirect(url_for('dashboard'))
        
        flash('Invalid credentials')
    
    return render_template('auth.html', mode='login')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# --- OAUTH ROUTES ---

@app.route('/auth/google')
def auth_google():
    if not GOOGLE_CLIENT_ID:
        flash('Google authentication is not configured', 'error')
        return redirect(url_for('login'))
    
    google_auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        "response_type=code&"
        "scope=openid%20email%20profile&"
        f"redirect_uri={url_for('auth_google_callback', _external=True)}"
    )
    return redirect(google_auth_url)

@app.route('/auth/google/callback')
def auth_google_callback():
    code = request.args.get('code')
    if not code:
        flash('Authentication failed', 'error')
        return redirect(url_for('login'))
    
    try:
        token_url = "https://oauth2.googleapis.com/token"
        token_data = {
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': url_for('auth_google_callback', _external=True)
        }
        
        token_response = requests.post(token_url, data=token_data)
        token_json = token_response.json()
        
        if 'access_token' not in token_json:
            flash('Authentication failed', 'error')
            return redirect(url_for('login'))
        
        userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        headers = {'Authorization': f"Bearer {token_json['access_token']}"}
        userinfo_response = requests.get(userinfo_url, headers=headers)
        userinfo = userinfo_response.json()
        
        user_data = users_collection.find_one({'auth_provider': 'google', 'auth_id': userinfo['id']})
        
        if not user_data:
            # Check if email exists
            existing_user = users_collection.find_one({'email': userinfo['email']})
            if existing_user:
                flash('An account with this email already exists', 'error')
                return redirect(url_for('login'))
            
            # Generate unique username
            username = userinfo['email'].split('@')[0]
            base_username = username
            counter = 1
            while users_collection.find_one({'username': username}):
                username = f"{base_username}{counter}"
                counter += 1
            
            # Create new user
            new_user_data = {
                'username': username,
                'email': userinfo['email'],
                'auth_provider': 'google',
                'auth_id': userinfo['id'],
                'created_at': datetime.utcnow()
            }
            result = users_collection.insert_one(new_user_data)
            new_user_data['_id'] = result.inserted_id
            user_data = new_user_data
        
        login_user(User(user_data))
        flash(f'Welcome back, {user_data["username"]}!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash('Authentication failed', 'error')
        return redirect(url_for('login'))

@app.route('/auth/github')
def auth_github():
    if not GITHUB_CLIENT_ID:
        flash('GitHub authentication is not configured', 'error')
        return redirect(url_for('login'))
    
    github_auth_url = (
        "https://github.com/login/oauth/authorize?"
        f"client_id={GITHUB_CLIENT_ID}&"
        f"redirect_uri={url_for('auth_github_callback', _external=True)}&"
        "scope=user:email"
    )
    return redirect(github_auth_url)

@app.route('/auth/github/callback')
def auth_github_callback():
    code = request.args.get('code')
    if not code:
        flash('Authentication failed', 'error')
        return redirect(url_for('login'))
    
    try:
        token_url = "https://github.com/login/oauth/access_token"
        token_data = {
            'client_id': GITHUB_CLIENT_ID,
            'client_secret': GITHUB_CLIENT_SECRET,
            'code': code,
            'redirect_uri': url_for('auth_github_callback', _external=True)
        }
        headers = {'Accept': 'application/json'}
        
        token_response = requests.post(token_url, data=token_data, headers=headers)
        token_json = token_response.json()
        
        if 'access_token' not in token_json:
            flash('Authentication failed', 'error')
            return redirect(url_for('login'))
        
        userinfo_url = "https://api.github.com/user"
        headers = {'Authorization': f"token {token_json['access_token']}"}
        userinfo_response = requests.get(userinfo_url, headers=headers)
        userinfo = userinfo_response.json()
        
        emails_url = "https://api.github.com/user/emails"
        emails_response = requests.get(emails_url, headers=headers)
        emails = emails_response.json()
        
        primary_email = next((email['email'] for email in emails if email['primary']), None)
        
        user_data = users_collection.find_one({'auth_provider': 'github', 'auth_id': str(userinfo['id'])})
        
        if not user_data:
            if primary_email:
                existing_user = users_collection.find_one({'email': primary_email})
                if existing_user:
                    flash('An account with this email already exists', 'error')
                    return redirect(url_for('login'))
            
            # Generate unique username
            username = userinfo['login']
            base_username = username
            counter = 1
            while users_collection.find_one({'username': username}):
                username = f"{base_username}{counter}"
                counter += 1
            
            # Create new user
            new_user_data = {
                'username': username,
                'email': primary_email,
                'auth_provider': 'github',
                'auth_id': str(userinfo['id']),
                'created_at': datetime.utcnow()
            }
            result = users_collection.insert_one(new_user_data)
            new_user_data['_id'] = result.inserted_id
            user_data = new_user_data
        
        login_user(User(user_data))
        flash(f'Welcome back, {user_data["username"]}!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash('Authentication failed', 'error')
        return redirect(url_for('login'))

# --- MAIN ROUTES ---

@app.route('/dashboard')
@login_required
def dashboard():
    # Get all portfolios for current user
    portfolios = list(portfolios_collection.find({'user_id': current_user.id}))
    
    # Convert ObjectId to string for template
    for p in portfolios:
        p['id'] = str(p['_id'])
    
    return render_template('dashboard.html', portfolios=portfolios)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        try:
            # Validate required fields
            required_fields = ['name', 'role', 'bio', 'email']
            for field in required_fields:
                if not request.form.get(field):
                    flash(f'{field.capitalize()} is required', 'error')
                    return redirect(url_for('create'))
            
            # Process files
            pic_data = None
            profile_pic_file = request.files.get('profile_pic')
            if profile_pic_file and profile_pic_file.filename:
                try:
                    pic_data = f"data:{profile_pic_file.mimetype};base64,{base64.b64encode(profile_pic_file.read()).decode('utf-8')}"
                except Exception as e:
                    flash('Error processing profile picture', 'error')
                    return redirect(url_for('create'))

            res_data = None
            resume_file = request.files.get('resume')
            if resume_file and resume_file.filename:
                try:
                    if resume_file.mimetype != 'application/pdf':
                        flash('Resume must be a PDF file', 'error')
                        return redirect(url_for('create'))
                    res_data = f"data:application/pdf;base64,{base64.b64encode(resume_file.read()).decode('utf-8')}"
                except Exception as e:
                    flash('Error processing resume file', 'error')
                    return redirect(url_for('create'))

            # Get theme preset
            theme_preset = request.form.get('theme_preset', 'cupertino')
            custom_color = None
            if theme_preset == 'custom':
                custom_color = request.form.get('custom_accent_color', '#0071e3')
            
            # Process projects
            projects = []
            titles = request.form.getlist('project_title[]')
            descriptions = request.form.getlist('project_desc[]')
            links = request.form.getlist('project_link[]')
            techs = request.form.getlist('project_tech[]')
            
            for i in range(len(titles)):
                if titles[i].strip():
                    projects.append({
                        'title': titles[i].strip(),
                        'desc': descriptions[i] if i < len(descriptions) else '',
                        'link': links[i] if i < len(links) else '',
                        'tech': techs[i] if i < len(techs) else ''
                    })

            # Process experiences
            experiences = []
            companies = request.form.getlist('exp_company[]')
            positions = request.form.getlist('exp_position[]')
            durations = request.form.getlist('exp_duration[]')
            exp_descriptions = request.form.getlist('exp_desc[]')
            
            for i in range(len(companies)):
                if companies[i].strip():
                    experiences.append({
                        'company': companies[i].strip(),
                        'position': positions[i] if i < len(positions) else '',
                        'duration': durations[i] if i < len(durations) else '',
                        'desc': exp_descriptions[i] if i < len(exp_descriptions) else ''
                    })
            
            # Create portfolio document
            portfolio_data = {
                'name': request.form.get('name', '').strip(),
                'role': request.form.get('role', '').strip(),
                'bio': request.form.get('bio', '').strip(),
                'email': request.form.get('email', '').strip(),
                'github': request.form.get('github', '').strip(),
                'linkedin': request.form.get('linkedin', '').strip(),
                'skills': request.form.get('skills', '').strip(),
                'theme_preset': theme_preset,
                'custom_accent_color': custom_color,
                'formspree_id': request.form.get('formspree_id', '').strip(),
                'live_url': request.form.get('live_url', '').strip(),
                'profile_pic': pic_data,
                'resume_data': res_data,
                'user_id': current_user.id,
                'projects': projects,
                'experiences': experiences,
                'created_at': datetime.utcnow()
            }
            
            result = portfolios_collection.insert_one(portfolio_data)
            
            flash('Portfolio created successfully!', 'success')
            return redirect(url_for('preview', p_id=str(result.inserted_id)))
            
        except Exception as e:
            print(f"Error creating portfolio: {str(e)}")
            print(traceback.format_exc())
            flash(f'Error creating portfolio: {str(e)}', 'error')
            return redirect(url_for('create'))
    
    return render_template('generator.html')

@app.route('/edit/<p_id>', methods=['GET', 'POST'])
@login_required
def edit(p_id):
    try:
        portfolio = portfolios_collection.find_one({'_id': ObjectId(p_id)})
    except:
        return "Invalid portfolio ID", 404
    
    if not portfolio:
        return "Portfolio not found", 404
    
    if portfolio['user_id'] != current_user.id:
        return "Unauthorized", 403
    
    if request.method == 'POST':
        try:
            # Update basic info
            update_data = {
                'name': request.form['name'],
                'role': request.form['role'],
                'bio': request.form['bio'],
                'email': request.form['email'],
                'github': request.form.get('github', ''),
                'linkedin': request.form.get('linkedin', ''),
                'skills': request.form.get('skills', ''),
                'formspree_id': request.form.get('formspree_id', ''),
                'live_url': request.form.get('live_url', ''),
                'theme_preset': request.form.get('theme_preset', 'cupertino'),
                'updated_at': datetime.utcnow()
            }
            
            # Update files if provided
            if request.files.get('profile_pic'):
                f = request.files['profile_pic']
                if f.filename:
                    update_data['profile_pic'] = f"data:{f.mimetype};base64,{base64.b64encode(f.read()).decode('utf-8')}"
            
            if request.files.get('resume'):
                f = request.files['resume']
                if f.filename and f.mimetype == 'application/pdf':
                    update_data['resume_data'] = f"data:application/pdf;base64,{base64.b64encode(f.read()).decode('utf-8')}"
            
            # Process projects
            projects = []
            titles = request.form.getlist('project_title[]')
            descriptions = request.form.getlist('project_desc[]')
            links = request.form.getlist('project_link[]')
            techs = request.form.getlist('project_tech[]')
            
            for i, title in enumerate(titles):
                if title.strip():
                    projects.append({
                        'title': title,
                        'desc': descriptions[i] if i < len(descriptions) else '',
                        'link': links[i] if i < len(links) else '',
                        'tech': techs[i] if i < len(techs) else ''
                    })
            
            update_data['projects'] = projects
            
            # Process experiences
            experiences = []
            companies = request.form.getlist('exp_company[]')
            positions = request.form.getlist('exp_position[]')
            durations = request.form.getlist('exp_duration[]')
            descs = request.form.getlist('exp_desc[]')

            for i, company in enumerate(companies):
                if company.strip():
                    experiences.append({
                        'company': company,
                        'position': positions[i] if i < len(positions) else '',
                        'duration': durations[i] if i < len(durations) else '',
                        'desc': descs[i] if i < len(descs) else ''
                    })
            
            update_data['experiences'] = experiences
            
            portfolios_collection.update_one(
                {'_id': ObjectId(p_id)},
                {'$set': update_data}
            )
            
            flash('Portfolio updated successfully!', 'success')
            return redirect(url_for('preview', p_id=p_id))
            
        except Exception as e:
            print(f"Error updating portfolio: {str(e)}")
            flash('Error updating portfolio', 'error')
            return redirect(url_for('edit', p_id=p_id))
    
    # Convert for template
    portfolio['id'] = str(portfolio['_id'])
    return render_template('edit.html', p=portfolio)

@app.route('/delete/<p_id>')
@login_required
def delete(p_id):
    try:
        portfolio = portfolios_collection.find_one({'_id': ObjectId(p_id)})
    except:
        return "Invalid portfolio ID", 404
    
    if not portfolio:
        return "Portfolio not found", 404
    
    if portfolio['user_id'] != current_user.id:
        return "Unauthorized", 403
    
    portfolios_collection.delete_one({'_id': ObjectId(p_id)})
    flash('Portfolio deleted successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/qr/<p_id>')
def qr_code(p_id):
    try:
        portfolio = portfolios_collection.find_one({'_id': ObjectId(p_id)})
    except:
        return "Invalid portfolio ID", 404
    
    if not portfolio:
        return "Portfolio not found", 404
    
    data = portfolio.get('live_url') or portfolio.get('linkedin') or "https://github.com"
    
    img = qrcode.make(data)
    mem = io.BytesIO()
    img.save(mem, 'PNG')
    mem.seek(0)
    return send_file(mem, mimetype='image/png')

@app.route('/preview/<p_id>')
def preview(p_id):
    try:
        portfolio = portfolios_collection.find_one({'_id': ObjectId(p_id)})
    except:
        return "Invalid portfolio ID", 404
    
    if not portfolio:
        return "Portfolio not found", 404
    
    portfolio['id'] = str(portfolio['_id'])
    skills = [s.strip() for s in portfolio.get('skills', '').split(',')] if portfolio.get('skills') else []
    return render_template('portfolio.html', p=portfolio, skills=skills, preview=True)

@app.route('/download/<p_id>')
def download(p_id):
    try:
        portfolio = portfolios_collection.find_one({'_id': ObjectId(p_id)})
    except:
        return "Invalid portfolio ID", 404
    
    if not portfolio:
        return "Portfolio not found", 404
    
    portfolio['id'] = str(portfolio['_id'])
    skills = [s.strip() for s in portfolio.get('skills', '').split(',')] if portfolio.get('skills') else []
    rendered = render_template('portfolio.html', p=portfolio, skills=skills, preview=False)
    mem = io.BytesIO()
    mem.write(rendered.encode('utf-8'))
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name=f"{portfolio['name'].replace(' ','_')}_portfolio.html", mimetype='text/html')

@app.route('/sample')
def sample():
    """Sample portfolio for landing page preview"""
    class SamplePortfolio:
        def __init__(self):
            self.id = 1
            self.name = "Alex Chen"
            self.role = "Full Stack Developer"
            self.bio = "Passionate about building scalable web applications with modern technologies. 5+ years of experience in full-stack development."
            self.email = "alex.chen@example.com"
            self.github = "https://github.com/alexchen"
            self.linkedin = "https://linkedin.com/in/alexchen"
            self.skills = "JavaScript, React, Node.js, Python, PostgreSQL"
            self.theme_preset = "cupertino"
            self.custom_accent_color = None
            self.profile_pic = None
            self.resume_data = None
            self.formspree_id = "xqwerty"
            self.live_url = "https://alexchen.dev"
            self.experiences = []
            self.projects = []
    
    sample_portfolio = SamplePortfolio()
    skills = [s.strip() for s in sample_portfolio.skills.split(',')] if sample_portfolio.skills else []
    return render_template('portfolio.html', p=sample_portfolio, skills=skills, preview=False)

if __name__ == '__main__':
    app.run(debug=True)