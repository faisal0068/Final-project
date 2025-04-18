from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, login_required, login_user, logout_user, current_user, UserMixin
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os

# Initialize app
app = Flask(__name__)
app.secret_key = '3d6576aa088c3c806bff9e02b3cff902c43c38b75c54fff24a53b236b324b535'  # Required for session management and flashing messages

# Setup database URI (adjust for your environment)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # Replace with PostgreSQL or MySQL if needed
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # To avoid overhead
db = SQLAlchemy(app)

# Setup login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Real User Model --- (SQLAlchemy ORM Model)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')
    files = db.relationship('File', backref='owner', lazy=True)

    @staticmethod
    def get(user_id):
        return User.query.get(user_id)

# --- File Model --- (SQLAlchemy ORM Model for File uploads)
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- Real user loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Routes

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']

        # Basic validation
        if not username or not email or not password:
            flash('Please fill out all fields.', 'danger')
            return redirect(url_for('register'))

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash('Email already registered. Try logging in.', 'warning')
            return redirect(url_for('register'))

        # Insert new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    users = User.query.all()

    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(user_id)

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_user.html', user=user)

@app.route('/admin/delete/<int:user_id>')
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')

    return redirect(url_for('admin_dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            # Password correct
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to a protected page
        else:
            flash('Incorrect email or password.', 'danger')

        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['username'])

@app.route('/my_files')
@login_required
def my_files():
    files = File.query.filter_by(user_id=current_user.id).all()

    files_data = []
    for file in files:
        extension = file.filename.split('.')[-1].lower()
        icon = get_icon_for_extension(extension)

        user_folder = os.path.join('uploads', str(current_user.id))
        filepath = os.path.join(user_folder, file.filename)
        
        if os.path.exists(filepath):
            size_bytes = os.path.getsize(filepath)
            size_mb = round(size_bytes / (1024 * 1024), 2)  # Convert to MB
        else:
            size_mb = 0

        files_data.append({
            'id': file.id,
            'filename': file.filename,
            'uploaded_at': file.uploaded_at,
            'icon': icon,
            'extension': extension,
            'size_mb': size_mb
        })

    return render_template('my_files.html', files=files_data)

def get_icon_for_extension(extension):
    mapping = {
        'pdf': 'fa-file-pdf',
        'jpg': 'fa-file-image',
        'jpeg': 'fa-file-image',
        'png': 'fa-file-image',
        'doc': 'fa-file-word',
        'docx': 'fa-file-word',
        'xls': 'fa-file-excel',
        'xlsx': 'fa-file-excel',
        'ppt': 'fa-file-powerpoint',
        'pptx': 'fa-file-powerpoint',
        'txt': 'fa-file-alt',
        'zip': 'fa-file-archive',
        'rar': 'fa-file-archive',
    }
    return mapping.get(extension, 'fa-file')  # Default icon

@app.route('/upload_file', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            user_folder = os.path.join('uploads', str(current_user.id))
            os.makedirs(user_folder, exist_ok=True)

            file_path = os.path.join(user_folder, filename)
            file.save(file_path)

            new_file = File(user_id=current_user.id, filename=filename)
            db.session.add(new_file)
            db.session.commit()

            flash('File uploaded successfully!', 'success')
            return redirect(url_for('my_files'))

    return render_template('upload_file.html')

@app.route('/delete_file/<int:file_id>')
@login_required
def delete_file(file_id):
    file = File.query.get(file_id)
    if file and file.user_id == current_user.id:
        file_path = os.path.join('uploads', str(current_user.id), file.filename)
        if os.path.exists(file_path):
            os.remove(file_path)

        db.session.delete(file)
        db.session.commit()
        flash('File deleted successfully!', 'success')

    return redirect(url_for('my_files'))

if __name__ == '__main__':
    db.create_all()  # Create the database tables if not already created
    app.run(debug=True)
