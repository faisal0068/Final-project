from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_required, login_user, logout_user, current_user, UserMixin
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import session, redirect, url_for, flash
import os
import sqlite3 

# Initialize app
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management and flashing messages


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
