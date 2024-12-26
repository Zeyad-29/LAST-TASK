from flask import Flask, render_template, request, redirect
import sqlite3

app = Flask(__name__)

# Insecure database connection (no parameterization)
def get_user_from_db(username):
    # TODO: Replace this insecure query with parameterized SQL to prevent SQL Injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"  # Vulnerable to SQL Injection
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    comments = []
    if request.method == 'POST':
        user_comment = request.form['comment']
        
        # TODO: Sanitize user input before saving it to prevent XSS
        with open('comments.txt', 'a') as f:
            f.write(user_comment + "\n")  # Save comment to a file (Unsanitized input)
        
    # Read all comments
    with open('comments.txt', 'r') as f:
        comments = f.readlines()
    
    # TODO: Escape comments when rendering to prevent XSS
    return render_template('comments.html', comments=comments)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    success = False
    if request.method == 'POST':
        recipient = request.form['recipient']
        amount = request.form['amount']
        
        # TODO: Implement CSRF protection using a CSRF token
        with open('transactions.txt', 'a') as f:
            f.write(f"Transfer to: {recipient}, Amount: {amount}\n")
        
        success = True
    
    return render_template('transfer.html', success=success)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Insecure login logic (No hashing or validation)
        # TODO: Use secure password hashing to store and verify passwords
        # TODO: Validate user input to prevent SQL Injection
        user = get_user_from_db(username)
        if user:  # Plaintext password comparison (No hashing)
            # TODO: Replace with secure password validation using hashed passwords
            return redirect('/')
        else:
            return 'Invalid credentials!', 400

    return render_template('login.html')

if __name__ == "__main__":
    app.run(debug=True)
