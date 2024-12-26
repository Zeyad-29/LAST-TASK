from flask import Flask, render_template, request, redirect, flash,session
from flask_wtf import FlaskForm
import html
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from email_validator import validate_email, EmailNotValidError
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import re
import time
from cryptography.fernet import Fernet
from flask_limiter.util import get_remote_address

from flask_limiter import Limiter


app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Required for flashing messages

# Initialize Flask-Limiter for rate-limiting to prevent abuse
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"]  # Default rate limit
)

# 1: Input Validation Function
def validate_text(input_text):
    """
    Validates input to allow only alphanumeric characters, spaces, and basic punctuation.
    This helps prevent injection attacks like SQL Injection and XSS.
    """
    if re.match(r"^[a-zA-Z0-9 .,!?'-]+$", input_text):
        return True
    return False

# Encryption: Load the encryption key from a file
def load_key():
    with open("encryption_key.key", "rb") as key_file:
        return key_file.read()

# Encrypt data for sensitive storage
def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

# Decrypt data for retrieval of sensitive information
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()

# Secure Database Query: Fetch user and verify password
def get_user_from_db(username, password):
    """
    Fetches a user securely using parameterized queries and validates the password.
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Secure query using parameterized SQL to prevent SQL Injection
    query = "SELECT username, password FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        stored_username, stored_password_hash = user
        # Validate password hash
        if check_password_hash(stored_password_hash, password):
            return stored_username
        else:
            return None  # Invalid password
    return None  # User not found

# Check for duplicate users during registration
def is_duplicate_user(username, email):
    """
    Check the database to ensure no duplicate username or email exists.
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email))
    user = cursor.fetchone()
    conn.close()
    return user

# Custom Logging: Log events for auditing and debugging
def log_event(event_type, message):
    """Logs security events to a custom log file."""
    with open('custom_security_logs.txt', 'a') as log_file:
        log_file.write(f"{event_type}: {message}\n")

# Log Suspicious Activity
def log_suspicious_activity(username, ip_address, message):
    """Logs suspicious activities for monitoring purposes."""
    with open("suspicious_activity.log", "a") as log_file:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        log_file.write(f"[{timestamp}] Username: {username}, IP: {ip_address}, Message: {message}\n")
    print(f"Suspicious activity logged: {message}")

# Detect SQL Injection Patterns in Input
def detect_sql_injection(input_text):
    """Detect potential SQL Injection patterns in input."""
    sql_patterns = [r"(?i)(SELECT|DROP|INSERT|DELETE|UPDATE|--|;|')"]
    for pattern in sql_patterns:
        if re.search(pattern, input_text):
            return True
    return False

# Detect XSS Patterns in Input
def detect_xss(input_text):
    """Detect potential XSS patterns in input."""
    xss_patterns = [r"<.*?>", r"javascript:", r"&lt;", r"&gt;"]
    for pattern in xss_patterns:
        if re.search(pattern, input_text):
            return True
    return False

# Registration Route: Validate and register a new user
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validation checks
        errors = []

        # Check username length
        if len(username) < 3 or len(username) > 20:
            errors.append("Username must be between 3 and 20 characters.")

        # Validate email format
        try:
            validate_email(email)
        except EmailNotValidError:
            errors.append("Invalid email format.")

        # Check password length and match
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        if password != confirm_password:
            errors.append("Passwords do not match.")

        # Check for duplicate user
        if is_duplicate_user(username, email):
            errors.append("Username or email already exists. Please try again.")

        # If there are errors, show them to the user
        if errors:
            return render_template('register.html', errors=errors, username=username, email=email)

        # Hash the password securely
        hashed_password = generate_password_hash(password)

        # Save user to the database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
                       (username, email, hashed_password))
        conn.commit()
        conn.close()

        flash("Registration successful! You can now log in.", "success")
        return redirect('/login')

    return render_template('register.html', errors=[])

# Home Route
@app.route('/')
def home():
    return render_template('home.html')

# Comment Route: Validate and sanitize user comments
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    comments = []
    if request.method == 'POST':
        user_comment = request.form['comment']

        # Validate user input
        if detect_xss(user_comment):
            log_event("XSS Attempt", f"Input: {user_comment}")
            log_suspicious_activity(session.get('username', 'Anonymous'), request.remote_addr, "Invalid input detected.")
            #return "Suspicious activity detected. Action logged.", 400

        if not validate_text(user_comment):
            pass
            #return "Invalid input: special characters are not allowed.", 400

        # Escape user input to prevent XSS
        user_comment = html.escape(user_comment)

        # Save sanitized comment
        with open('comments.txt', 'a') as f:
            f.write(user_comment + "\n")

    # Read and sanitize all comments for rendering
    with open('comments.txt', 'r') as f:
        comments = f.readlines()
    escaped_comments = [html.escape(comment.strip()) for comment in comments]
    return render_template('comments.html', comments=escaped_comments)

# Transfer Route: Simulate secure transactions
@app.route('/transfer', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit to prevent abuse
def transfer():
    success = False
    if request.method == 'POST':
        recipient = request.form['recipient']
        amount = request.form['amount']
        csrf_token = request.form.get('csrf_token')

        # Verify the CSRF token
        if csrf_token != session.get('csrf_token'):
            return "CSRF Token Mismatch! Request Denied.", 403

        # Validate user input
        if (not validate_text(recipient)) or (not validate_text(amount)):
            return "Invalid input: special characters are not allowed.", 400

        # Load encryption key
        key = load_key()

        # Encrypt transaction details
        encrypted_recipient = encrypt_data(recipient, key)
        encrypted_amount = encrypt_data(amount, key)

        # Save encrypted data to a file
        with open('transactions.txt', 'ab') as f:
            f.write(encrypted_recipient + b" | " + encrypted_amount + b"\n")

        success = True

    return render_template('transfer.html', success=success, csrf_token=session.get('csrf_token'))

# Login Route: Authenticate users securely
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit to prevent brute force

def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr  # Get the IP address of the client

        # Initialize session variables for failed logins if not already set
        if 'failed_logins' not in session:
            session['failed_logins'] = 0
            session['first_attempt_time'] = time.time()

        if detect_sql_injection(username) or detect_sql_injection(password):
            log_suspicious_activity(username, ip_address, "SQL Injection Attempt")
            return "Suspicious activity detected.", 400

        # Validate input
        if not validate_text(username) or not validate_text(password):
            flash("Invalid input detected!", "error")
            session['failed_logins'] += 1
            log_suspicious_activity(username, ip_address, "Invalid input detected.")
            return "Suspicious activity detected.", 400

        # Authenticate user
        authenticated_user = get_user_from_db(username, password)
        if authenticated_user:
            flash("Login successful!", "success")
            session['username'] = authenticated_user
            return render_template('account_page.html')
        else:
            flash("Invalid username or password.", "error")
            session['failed_logins'] += 1

    return render_template('login.html')

if __name__ == "__main__":
    app.run(debug=True)
