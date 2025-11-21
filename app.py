from flask import Flask, render_template, request, redirect, url_for, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import io
import base64
import qrcode
import os
from dotenv import load_dotenv

load_dotenv() 

# --- APP SETUP ---
app = Flask(__name__)

database_uri = os.environ.get('DATABASE_URL')
if database_uri and database_uri.startswith("postgres://"):
    database_uri = database_uri.replace("postgres://", "postgresql://", 1)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'b42907f1d8325fda2d3fcd6917c2f910437602425099d321c9dab187b04d89a5y') 
app.config['SQLALCHEMY_DATABASE_URI'] = database_uri or 'sqlite:///instance/portfolios.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- MODELS ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
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
    custom_accent_color = db.Column(db.String(7), nullable=True) # Stores HEX code
    
    # Files (Base64)
    profile_pic = db.Column(db.Text, nullable=True)
    resume_data = db.Column(db.Text, nullable=True)
    
    # New Features
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
    if 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI'] and not os.path.exists('instance'):
        os.makedirs('instance')
    
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- AUTH ROUTES ---

@app.route('/')
def home():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username taken'); return redirect(url_for('register'))
        new_user = User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user); db.session.commit(); login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('auth.html', mode='register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user); return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('auth.html', mode='login')

@app.route('/logout')
@login_required
def logout(): logout_user(); return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard(): return render_template('dashboard.html', portfolios=current_user.portfolios)


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        # Files
        pic_data = None
        if request.files.get('profile_pic'):
            f = request.files['profile_pic']
            if f.filename: pic_data = f"data:{f.mimetype};base64,{base64.b64encode(f.read()).decode('utf-8')}"
        
        res_data = None
        if request.files.get('resume'):
            f = request.files['resume']
            if f.filename and f.mimetype=='application/pdf': res_data = f"data:application/pdf;base64,{base64.b64encode(f.read()).decode('utf-8')}"

        # Custom Color Logic
        custom_color = None
        theme_preset = request.form['theme_preset']
        if theme_preset == 'custom':
            custom_color = request.form.get('custom_accent_color', '#0071e3')
        
        new_portfolio = Portfolio(
            name=request.form['name'], role=request.form['role'], bio=request.form['bio'],
            email=request.form['email'], github=request.form['github'], linkedin=request.form['linkedin'],
            skills=request.form['skills'], theme_preset=theme_preset,
            custom_accent_color=custom_color, # New field assignment
            formspree_id=request.form['formspree_id'], live_url=request.form['live_url'],
            profile_pic=pic_data, resume_data=res_data, user_id=current_user.id
        )
        db.session.add(new_portfolio); db.session.flush()

        # Loops for dynamic sections
        for i, t in enumerate(request.form.getlist('project_title[]')):
            if t.strip(): db.session.add(Project(title=t, desc=request.form.getlist('project_desc[]')[i], link=request.form.getlist('project_link[]')[i], tech=request.form.getlist('project_tech[]')[i], portfolio_id=new_portfolio.id))
        
        for i, c in enumerate(request.form.getlist('exp_company[]')):
            if c.strip(): db.session.add(Experience(company=c, position=request.form.getlist('exp_position[]')[i], duration=request.form.getlist('exp_duration[]')[i], desc=request.form.getlist('exp_desc[]')[i], portfolio_id=new_portfolio.id))

        db.session.commit()
        return redirect(url_for('preview', p_id=new_portfolio.id))
    
    return render_template('generator.html')

@app.route('/delete/<int:p_id>')
@login_required
def delete(p_id):
    p = Portfolio.query.get_or_404(p_id)
    if p.author != current_user: return "Unauthorized", 403
    db.session.delete(p); db.session.commit()
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
@app.route('/download/<int:p_id>')
def preview(p_id):
    p = Portfolio.query.get_or_404(p_id)
    skills = [s.strip() for s in p.skills.split(',')] if p.skills else []
    template_mode = True if 'preview' in request.path else False
    
    if not template_mode:
        rendered = render_template('portfolio.html', p=p, skills=skills, preview=False)
        mem = io.BytesIO(); mem.write(rendered.encode('utf-8')); mem.seek(0)
        return send_file(mem, as_attachment=True, download_name=f"{p.name.replace(' ','_')}_portfolio.html", mimetype='text/html')
    
    return render_template('portfolio.html', p=p, skills=skills, preview=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)