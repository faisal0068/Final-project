import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', '3d6576aa088c3c806bff9e02b3cff902c43c38b75c54fff24a53b236b324b535')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

if not os.path.exists('uploads'):
    os.makedirs('uploads')

def init_db():
    with sqlite3.connect('storage.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        filename TEXT,
                        saved_name TEXT)''')
        conn.commit()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = generate_password_hash(request.form['password'])
    with sqlite3.connect('storage.db') as conn:
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
            flash("Registered successfully. Please login.", "success")
        except sqlite3.IntegrityError:
            flash("Username already exists.", "danger")
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    with sqlite3.connect('storage.db') as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
            return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('index'))
    with sqlite3.connect('storage.db') as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM files WHERE user_id = ?', (session['user_id'],))
        files = c.fetchall()
    return render_template('dashboard.html', files=files)

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        flash("You must be logged in to upload.", "danger")
        return redirect(url_for('index'))
    file = request.files['file']
    if file:
        filename = secure_filename(file.filename)
        saved_name = f"{session['user_id']}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], saved_name))
        with sqlite3.connect('storage.db') as conn:
            c = conn.cursor()
            c.execute('INSERT INTO files (user_id, filename, saved_name) VALUES (?, ?, ?)',
                      (session['user_id'], filename, saved_name))
            conn.commit()
        flash('File uploaded successfully!', 'success')
    else:
        flash('No file selected!', 'warning')
    return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
def download(file_id):
    if 'user_id' not in session:
        flash("Login required.", "warning")
        return redirect(url_for('index'))
    with sqlite3.connect('storage.db') as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM files WHERE id = ? AND user_id = ?', (file_id, session['user_id']))
        file = c.fetchone()
        if file:
            return send_from_directory(app.config['UPLOAD_FOLDER'], file[3], as_attachment=True)
    flash("File not found.", "danger")
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:file_id>')
def delete(file_id):
    if 'user_id' not in session:
        flash("Login required.", "warning")
        return redirect(url_for('index'))
    with sqlite3.connect('storage.db') as conn:
        c = conn.cursor()
        c.execute('SELECT saved_name FROM files WHERE id = ? AND user_id = ?', (file_id, session['user_id']))
        file = c.fetchone()
        if file:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file[0]))
            c.execute('DELETE FROM files WHERE id = ?', (file_id,))
            conn.commit()
            flash("File deleted successfully.", "success")
        else:
            flash("File not found or unauthorized.", "danger")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
