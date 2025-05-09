from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_required, login_user, logout_user, current_user, UserMixin
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_sqlalchemy import SQLAlchemy
from flask import send_from_directory
from datetime import datetime



# Initialize app
app = Flask(__name__)
app.secret_key = '3d6576aa088c3c806bff9e02b3cff902c43c38b75c54fff24a53b236b324b535'

# Setup database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Setup login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Initialize DB tables if not already
with app.app_context():
    db.create_all()

# Routes

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # get form data
        username = request.form['username']
        password = request.form['password']
        
        # (your logic to verify username and password)

        if username == 'admin' and password == 'admin':  # example login check
            session['user'] = username
            return redirect(url_for('profile'))  # <-- redirect to profile page after login
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')
    

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please login or use a different email.', 'danger')
            return redirect(url_for('register'))
        
        new_user = User(username=username, email=email, password=password, role='user')
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)


@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Admin routes
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']
        db.session.commit()

        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_user.html', user=user)

@app.route('/download_file/<filename>')
@login_required
def download_file(filename):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    try:
        return send_from_directory(user_folder, filename, as_attachment=True)
    except FileNotFoundError:
        flash('File not found.', 'danger')
        return redirect(url_for('my_files'))

@app.route('/preview/<filename>')
@login_required
def preview_file(filename):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    return send_from_directory(user_folder, filename)


@app.route('/admin/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()

    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

# File upload routes
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/my_files')
@login_required
def my_files():
    user_folder = os.path.join(UPLOAD_FOLDER, str(current_user.id))
    os.makedirs(user_folder, exist_ok=True)  # Create if doesn't exist
    files = os.listdir(user_folder)
    return render_template('my_files.html', files=files)

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

            flash('File uploaded successfully!', 'success')
            return redirect(url_for('my_files'))

    return render_template('upload_file.html')

@app.route('/delete_file/<filename>')
@login_required
def delete_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, str(current_user.id), filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash('File deleted successfully!', 'success')
    else:
        flash('File not found.', 'danger')
    
    return redirect(url_for('my_files'))

# User settings and profile routes
@app.route('/profile')
def profile():
    # Dummy user data, replace with actual database queries later
    user = {
        'username': 'John Doe',
        'email': 'john@example.com',
        'files_count': 25,
        'storage_used': 120,  # in MB
        'join_date': datetime(2024, 1, 15)
    }
    return render_template('profile.html', user=user)

@app.route('/update_email', methods=['GET', 'POST'])
@login_required
def update_email():
    if request.method == 'POST':
        new_email = request.form.get('new_email')
        password = request.form.get('password')

        if not new_email or not password:
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('update_email'))

        user = User.query.get(current_user.id)
        if check_password_hash(user.password, password):
            existing_user = User.query.filter_by(email=new_email).first()
            if existing_user:
                flash('This email is already registered. Please choose a different one.', 'danger')
            else:
                user.email = new_email
                db.session.commit()
                flash('Email updated successfully!', 'success')
                return redirect(url_for('profile'))
        else:
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

        if not check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('update_password'))

        if new_password != confirm_new_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('update_password'))

        if len(new_password) < 6:
            flash('New password must be at least 6 characters long.', 'danger')
            return redirect(url_for('update_password'))

        current_user.password = generate_password_hash(new_password)
        db.session.commit()

        flash('Password updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('update_password.html')

if __name__ == '__main__':
    app.run(debug=True)
