from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_required, login_user, logout_user, current_user, UserMixin
from werkzeug.utils import secure_filename
import os

# Initialize app
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management and flashing messages

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

# Dummy User Class (you should replace this with your real User model)
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Dummy user loader (replace with DB query)
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Routes

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Dummy login (replace with your real login logic)
    if request.method == 'POST':
        user = User(id=1)
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

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
