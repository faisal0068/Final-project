import os
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

# Initialize Flask app and SQLAlchemy
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', '3d6576aa088c3c806bff9e02b3cff902c43c38b75c54fff24a53b236b324b535')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///storage.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Ensure the uploads directory exists
if not os.path.exists('uploads'):
    os.makedirs('uploads')

# Define models for Users and Files
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(120), nullable=False)
    saved_name = db.Column(db.String(120), nullable=False)

# Create the tables in the database
db.create_all()

# Allowed file types
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = generate_password_hash(request.form['password'])
    
    try:
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        flash("Registered successfully. Please login.", "success")
    except:
        db.session.rollback()
        flash("Username already exists.", "danger")
    
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('index'))
    
    files = File.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', files=files)

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        flash("You must be logged in to upload.", "danger")
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        saved_name = f"{session['user_id']}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], saved_name))
        
        new_file = File(user_id=session['user_id'], filename=filename, saved_name=saved_name)
        db.session.add(new_file)
        db.session.commit()
        
        flash('File uploaded successfully!', 'success')
    else:
        flash('Invalid file type or no file selected!', 'warning')
    
    return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
def download(file_id):
    if 'user_id' not in session:
        flash("Login required.", "warning")
        return redirect(url_for('index'))
    
    file = File.query.filter_by(id=file_id, user_id=session['user_id']).first()
    if file:
        return send_from_directory(app.config['UPLOAD_FOLDER'], file.saved_name, as_attachment=True)
    flash("File not found.", "danger")
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:file_id>')
def delete(file_id):
    if 'user_id' not in session:
        flash("Login required.", "warning")
        return redirect(url_for('index'))
    
    file = File.query.filter_by(id=file_id, user_id=session['user_id']).first()
    if file:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file.saved_name))
        db.session.delete(file)
        db.session.commit()
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
