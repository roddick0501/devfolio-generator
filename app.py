from flask import Flask, render_template, request, redirect, url_for, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import io
import base64
import qrcode
import os
import requests
from dotenv import load_dotenv

load_dotenv() 

# --- APP SETUP ---
app = Flask(__name__)

database_uri = os.environ.get('DATABASE_URL')
if database_uri and database_uri.startswith("postgres://"):
    database_uri = database_uri.replace("postgres://", "postgresql://", 1)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'b42907f1d8325fda2d3fcd6917c2f910437602425099d321c9dab187b04d89a5y') 

# Fixed database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = database_uri or f'sqlite:///{os.path.join(basedir, "instance", "portfolios.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')

# --- MODELS ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=True)
    password = db.Column(db.String(200), nullable=True)
    auth_provider = db.Column(db.String(20), default='local')
    auth_id = db.Column(db.String(100), nullable=True)
    portfolios = db.relationship('Portfolio', backref='author', lazy=True)

class Portfolio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False)
    bio = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(100))
    github = db.Column(db.String(100))
    linkedin = db.Column(db.String(100))
    skills = db.Column(db.String(200))
    
    theme_preset = db.Column(db.String(50), default="cupertino") 
    custom_accent_color = db.Column(db.String(7), nullable=True)
    
    profile_pic = db.Column(db.Text, nullable=True)
    resume_data = db.Column(db.Text, nullable=True)
    
    formspree_id = db.Column(db.String(50), nullable=True)
    live_url = db.Column(db.String(200), nullable=True)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    projects = db.relationship('Project', backref='portfolio', lazy=True, cascade="all, delete-orphan")
    experiences = db.relationship('Experience', backref='portfolio', lazy=True, cascade="all, delete-orphan")

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    desc = db.Column(db.Text, nullable=False)
    link = db.Column(db.String(200))
    tech = db.Column(db.String(100))
    portfolio_id = db.Column(db.Integer, db.ForeignKey('portfolio.id'), nullable=False)

class Experience(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(100), nullable=False)
    duration = db.Column(db.String(50), nullable=False)
    desc = db.Column(db.Text, nullable=True)
    portfolio_id = db.Column(db.Integer, db.ForeignKey('portfolio.id'), nullable=False)

# --- DATABASE INITIALIZATION ---
with app.app_context():
    instance_dir = os.path.join(basedir, 'instance')
    if not os.path.exists(instance_dir):
        os.makedirs(instance_dir)
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username taken')
            return redirect(url_for('register'))
        new_user = User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('auth.html', mode='register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.auth_provider == 'local' and check_password_hash(user.password, request.form['password']):
            login_user(user)
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
        
        user = User.query.filter_by(auth_provider='google', auth_id=userinfo['id']).first()
        if not user:
            existing_user = User.query.filter_by(email=userinfo['email']).first()
            if existing_user:
                flash('An account with this email already exists', 'error')
                return redirect(url_for('login'))
            
            username = userinfo['email'].split('@')[0]
            base_username = username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1
            
            user = User(
                username=username,
                email=userinfo['email'],
                auth_provider='google',
                auth_id=userinfo['id']
            )
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        flash(f'Welcome back, {user.username}!', 'success')
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
        
        user = User.query.filter_by(auth_provider='github', auth_id=str(userinfo['id'])).first()
        if not user:
            if primary_email:
                existing_user = User.query.filter_by(email=primary_email).first()
                if existing_user:
                    flash('An account with this email already exists', 'error')
                    return redirect(url_for('login'))
            
            username = userinfo['login']
            base_username = username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1
            
            user = User(
                username=username,
                email=primary_email,
                auth_provider='github',
                auth_id=str(userinfo['id'])
            )
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash('Authentication failed', 'error')
        return redirect(url_for('login'))

# --- MAIN ROUTES ---

@app.route('/dashboard')
@login_required
def dashboard(): 
    return render_template('dashboard.html', portfolios=current_user.portfolios)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        try:
            # Files
            pic_data = None
            if request.files.get('profile_pic'):
                f = request.files['profile_pic']
                if f.filename: 
                    pic_data = f"data:{f.mimetype};base64,{base64.b64encode(f.read()).decode('utf-8')}"
            
            res_data = None
            if request.files.get('resume'):
                f = request.files['resume']
                if f.filename and f.mimetype=='application/pdf': 
                    res_data = f"data:application/pdf;base64,{base64.b64encode(f.read()).decode('utf-8')}"

            # Get theme preset
            theme_preset = request.form.get('theme_preset', 'cupertino')
            custom_color = None
            if theme_preset == 'custom':
                custom_color = request.form.get('custom_accent_color', '#0071e3')
            
            new_portfolio = Portfolio(
                name=request.form.get('name', ''),
                role=request.form.get('role', ''),
                bio=request.form.get('bio', ''),
                email=request.form.get('email', ''),
                github=request.form.get('github', ''),
                linkedin=request.form.get('linkedin', ''),
                skills=request.form.get('skills', ''),
                theme_preset=theme_preset,
                custom_accent_color=custom_color,
                formspree_id=request.form.get('formspree_id', ''),
                live_url=request.form.get('live_url', ''),
                profile_pic=pic_data,
                resume_data=res_data,
                user_id=current_user.id
            )
            db.session.add(new_portfolio)
            db.session.flush()

            # Projects
            for i, t in enumerate(request.form.getlist('project_title[]')):
                if t.strip():
                    db.session.add(Project(
                        title=t,
                        desc=request.form.getlist('project_desc[]')[i],
                        link=request.form.getlist('project_link[]')[i],
                        tech=request.form.getlist('project_tech[]')[i],
                        portfolio_id=new_portfolio.id
                    ))
            
            # Experiences
            for i, c in enumerate(request.form.getlist('exp_company[]')):
                if c.strip():
                    db.session.add(Experience(
                        company=c,
                        position=request.form.getlist('exp_position[]')[i],
                        duration=request.form.getlist('exp_duration[]')[i],
                        desc=request.form.getlist('exp_desc[]')[i],
                        portfolio_id=new_portfolio.id
                    ))

            db.session.commit()
            flash('Portfolio created successfully!', 'success')
            return redirect(url_for('preview', p_id=new_portfolio.id))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error creating portfolio: {str(e)}")
            flash(f'Error creating portfolio. Please try again.', 'error')
            return redirect(url_for('create'))
    
    return render_template('generator.html')

@app.route('/edit/<int:p_id>', methods=['GET', 'POST'])
@login_required
def edit(p_id):
    p = Portfolio.query.get_or_404(p_id)
    if p.author != current_user:
        return "Unauthorized", 403
    
    if request.method == 'POST':
        try:
            # Update basic info
            p.name = request.form['name']
            p.role = request.form['role']
            p.bio = request.form['bio']
            p.email = request.form['email']
            p.github = request.form.get('github', '')
            p.linkedin = request.form.get('linkedin', '')
            p.skills = request.form.get('skills', '')
            p.formspree_id = request.form.get('formspree_id', '')
            p.live_url = request.form.get('live_url', '')
            
            # Update theme
            p.theme_preset = request.form.get('theme_preset', 'cupertino')
            
            # Update files if provided
            if request.files.get('profile_pic'):
                f = request.files['profile_pic']
                if f.filename:
                    p.profile_pic = f"data:{f.mimetype};base64,{base64.b64encode(f.read()).decode('utf-8')}"
            
            if request.files.get('resume'):
                f = request.files['resume']
                if f.filename and f.mimetype == 'application/pdf':
                    p.resume_data = f"data:application/pdf;base64,{base64.b64encode(f.read()).decode('utf-8')}"
            
            # Delete existing projects and experiences
            Project.query.filter_by(portfolio_id=p.id).delete()
            Experience.query.filter_by(portfolio_id=p.id).delete()
            
            # Add updated projects
            titles = request.form.getlist('project_title[]')
            for i, title in enumerate(titles):
                if title.strip():
                    proj = Project(
                        title=title,
                        desc=request.form.getlist('project_desc[]')[i],
                        link=request.form.getlist('project_link[]')[i],
                        tech=request.form.getlist('project_tech[]')[i],
                        portfolio_id=p.id
                    )
                    db.session.add(proj)
            
            # Add updated experiences
            companies = request.form.getlist('exp_company[]')
            for i, company in enumerate(companies):
                if company.strip():
                    exp = Experience(
                        company=company,
                        position=request.form.getlist('exp_position[]')[i],
                        duration=request.form.getlist('exp_duration[]')[i],
                        desc=request.form.getlist('exp_desc[]')[i],
                        portfolio_id=p.id
                    )
                    db.session.add(exp)
            
            db.session.commit()
            flash('Portfolio updated successfully!', 'success')
            return redirect(url_for('preview', p_id=p.id))
        except Exception as e:
            db.session.rollback()
            flash('Error updating portfolio', 'error')
            return redirect(url_for('edit', p_id=p.id))
    
    return render_template('edit.html', p=p)

@app.route('/delete/<int:p_id>')
@login_required
def delete(p_id):
    p = Portfolio.query.get_or_404(p_id)
    if p.author != current_user:
        return "Unauthorized", 403
    db.session.delete(p)
    db.session.commit()
    flash('Portfolio deleted successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/qr/<int:p_id>')
def qr_code(p_id):
    p = Portfolio.query.get_or_404(p_id)
    data = p.live_url if p.live_url else (p.linkedin if p.linkedin else "https://github.com")
    
    img = qrcode.make(data)
    mem = io.BytesIO()
    img.save(mem, 'PNG')
    mem.seek(0)
    return send_file(mem, mimetype='image/png')

@app.route('/preview/<int:p_id>')
def preview(p_id):
    p = Portfolio.query.get_or_404(p_id)
    skills = [s.strip() for s in p.skills.split(',')] if p.skills else []
    return render_template('portfolio.html', p=p, skills=skills, preview=True)

@app.route('/download/<int:p_id>')
def download(p_id):
    p = Portfolio.query.get_or_404(p_id)
    skills = [s.strip() for s in p.skills.split(',')] if p.skills else []
    rendered = render_template('portfolio.html', p=p, skills=skills, preview=False)
    mem = io.BytesIO()
    mem.write(rendered.encode('utf-8'))
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name=f"{p.name.replace(' ','_')}_portfolio.html", mimetype='text/html')

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