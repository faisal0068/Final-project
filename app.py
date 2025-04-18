from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_required, login_user, logout_user, current_user, UserMixin
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import os
import sqlite3 

# Initialize app
app = Flask(__name__)
app.secret_key = '3d6576aa088c3c806bff9e02b3cff902c43c38b75c54fff24a53b236b324b535'  # Required for session management and flashing messages

# Setup database URI (adjust for your environment)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # Replace with PostgreSQL or MySQL if needed
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # To avoid overhead
db = SQLAlchemy(app)

# Initialize SQLAlchemy
db = SQLAlchemy()
db.init_app(app)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def get_db_connection():
    conn = sqlite3.connect('database.db')  # Adjust path if needed
    conn.row_factory = sqlite3.Row
    return conn

# Configurations
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create uploads folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Setup login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Real User Class ---
class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

    @staticmethod
    def get(user_id):
        conn = sqlite3.connect('database.db')  # your actual DB
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email, role FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()

        if user:
            return User(id=user[0], username=user[1], email=user[2], role=user[3])
        else:
            return None

# --- Real user loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


# Routes

@app.route("/test")
def home():
    return "Hello, Waitress + Flask!"


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

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user already exists
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Email already registered. Try logging in.', 'warning')
            conn.close()
            return redirect(url_for('register'))

        # Insert new user
        hashed_password = generate_password_hash(password)

        cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                       (username, email, hashed_password))
        conn.commit()
        conn.close()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('your_database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, role, created_at FROM users')
    users = cursor.fetchall()
    conn.close()

    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('your_database.db')
    cursor = conn.cursor()

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        cursor.execute('UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?', (username, email, role, user_id))
        conn.commit()
        conn.close()
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    cursor.execute('SELECT id, username, email, role FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()

    return render_template('edit_user.html', user=user)

@app.route('/admin/delete/<int:user_id>')
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('your_database.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        print(request.form)
        email = request.form['email'].strip().lower()
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            stored_password = user['password']
            if check_password_hash(stored_password, password):
                # Password correct
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash('Logged in successfully!', 'success')
                return redirect(url_for('dashboard'))  # Redirect to a protected page
            else:
                flash('Incorrect password.', 'danger')
        else:
            flash('Email not found. Please register.', 'warning')
        
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/update_email', methods=['GET', 'POST'])
@login_required
def update_email():
    if request.method == 'POST':
        new_email = request.form.get('new_email')
        password = request.form.get('password')

        if not new_email or not password:
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('update_email'))

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the new email already exists
        cursor.execute('SELECT id FROM users WHERE email = ?', (new_email,))
        existing_user = cursor.fetchone()
        if existing_user:
            conn.close()
            flash('This email is already registered. Please choose a different one.', 'danger')
            return redirect(url_for('update_email'))

        # Get the user's current hashed password from database
        cursor.execute('SELECT password FROM users WHERE id = ?', (current_user.id,))
        user_data = cursor.fetchone()

        if user_data and check_password_hash(user_data['password'], password):
            try:
                cursor.execute('UPDATE users SET email = ? WHERE id = ?', (new_email, current_user.id))
                conn.commit()
                flash('Email updated successfully!', 'success')
            except Exception as e:
                print(f"Error updating email: {e}")
                flash('An error occurred. Please try again.', 'danger')
            finally:
                conn.close()
            return redirect(url_for('profile'))  # Redirect wherever you want
        else:
            conn.close()
            flash('Incorrect password. Please try again.', 'danger')
            return redirect(url_for('update_email'))

    return render_template('update_email.html')

@app.route('/update_password', methods=['GET', 'POST'])
@login_required
def update_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('update_password'))

        if new_password != confirm_new_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('update_password'))

        if len(new_password) < 6:
            flash('New password must be at least 6 characters long.', 'danger')
            return redirect(url_for('update_password'))

        # Update the password
        hashed_password = generate_password_hash(new_password)
        cursor = get_db().cursor()
        cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, current_user.id))
        get_db().commit()

        flash('Password updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('update_password.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', username=session['username'])

@app.route('/my_files')
@login_required
def my_files():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id, filename, uploaded_at FROM files WHERE user_id = ?', (current_user.id,))
    files_data = cursor.fetchall()

    files = []
    for file in files_data:
        extension = file['filename'].split('.')[-1].lower()
        icon = get_icon_for_extension(extension)

        user_folder = os.path.join('uploads', str(current_user.id))
        filepath = os.path.join(user_folder, file['filename'])
        
        if os.path.exists(filepath):
            size_bytes = os.path.getsize(filepath)
            size_mb = round(size_bytes / (1024 * 1024), 2)  # Convert to MB
        else:
            size_mb = 0

        files.append({
            'id': file['id'],
            'filename': file['filename'],
            'uploaded_at': file['uploaded_at'],
            'icon': icon,
            'extension': extension,
            'size_mb': size_mb
        })

    return render_template('my_files.html', files=files)

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
            user_folder = os.path.join(UPLOAD_FOLDER, str(current_user.id))
            os.makedirs(user_folder, exist_ok=True)

            file_path = os.path.join(user_folder, filename)
            file.save(file_path)

            cursor = get_db().cursor()
            cursor.execute('INSERT INTO files (user_id, filename, uploaded_at) VALUES (?, ?, CURRENT_TIMESTAMP)', (current_user.id, filename))
            get_db().commit()

            flash('File uploaded successfully!', 'success')
            return redirect(url_for('my_files'))

    return render_template('upload_file.html')


@app.route('/delete_file/<int:file_id>')
@login_required
def delete_file(file_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT filename FROM files WHERE id = ? AND user_id = ?', (file_id, current_user.id))
    file = cursor.fetchone()

    if file:
        filepath = os.path.join('uploads', str(current_user.id), file['filename'])
        if os.path.exists(filepath):
            os.remove(filepath)

        cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))
        db.commit()
        flash('File deleted successfully!', 'success')

    return redirect(url_for('my_files'))


# ✅ Upload Route
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('dashboard'))
    
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash('File uploaded successfully!', 'success')
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
