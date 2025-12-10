from flask import Flask, request, render_template_string, session, redirect, url_for
import secrets

app = Flask(__name__)
app.secret_key = 'insecure_secret_key_12345'

# Mock user database
users = {
    'admin': {'password': 'admin123', 'role': 'admin', 'id': 1},
    'user': {'password': 'user123', 'role': 'user', 'id': 2},
    'guest': {'password': 'guest123', 'role': 'guest', 'id': 3}
}

# Mock user data
user_data = {
    1: {'name': 'Admin User', 'email': 'admin@test.com', 'secret': 'admin_secret_data'},
    2: {'name': 'Regular User', 'email': 'user@test.com', 'secret': 'user_secret_data'},
    3: {'name': 'Guest User', 'email': 'guest@test.com', 'secret': 'guest_secret_data'}
}

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Auth Bypass Test App</title>
            <style>
                body { font-family: Arial; margin: 40px; background: #f0f0f0; }
                .container { background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: auto; }
                input { padding: 10px; margin: 10px 0; width: 100%; box-sizing: border-box; }
                button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }
                button:hover { background: #0056b3; }
                .warning { color: red; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 Authentication Bypass Test App</h1>
                <p class="warning">⚠️ This is a DELIBERATELY VULNERABLE test application!</p>
                
                <form action="/login" method="POST">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
                
                <div style="margin-top: 20px;">
                    <h3>Test Credentials:</h3>
                    <p>admin / admin123 (admin)<br>user / user123 (user)<br>guest / guest123 (guest)</p>
                </div>
                
                <div style="margin-top: 20px;">
                    <h3>Vulnerability Tests:</h3>
                    <p>1. Try accessing /dashboard directly without login</p>
                    <p>2. Try /api/user/1 to access other user's data (IDOR)</p>
                    <p>3. Try /admin without authentication</p>
                    <p>4. Manipulate session or user_id parameter</p>
                </div>
            </div>
        </body>
        </html>
    ''')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Vulnerable: Weak authentication
    if username in users and users[username]['password'] == password:
        session['username'] = username
        session['user_id'] = users[username]['id']
        session['role'] = users[username]['role']
        return redirect(url_for('dashboard'))
    
    return 'Invalid credentials! <a href="/">Try again</a>'

@app.route('/dashboard')
def dashboard():
    # Vulnerable: No proper session validation
    if 'username' not in session:
        # Weak check - can be bypassed
        return redirect(url_for('index'))
    
    username = session.get('username')
    role = session.get('role')
    user_id = session.get('user_id')
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard</title>
            <style>
                body { font-family: Arial; margin: 40px; background: #f0f0f0; }
                .container { background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: auto; }
                .info { background: #d4edda; padding: 15px; margin: 10px 0; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Dashboard</h1>
                <div class="info">
                    <p>Welcome, <strong>{{ username }}</strong>!</p>
                    <p>Role: {{ role }}</p>
                    <p>User ID: {{ user_id }}</p>
                </div>
                
                <div style="margin-top: 20px;">
                    <a href="/profile?id={{ user_id }}">View Profile</a> |
                    <a href="/api/user/{{ user_id }}">API Data</a> |
                    {% if role == 'admin' %}
                    <a href="/admin">Admin Panel</a> |
                    {% endif %}
                    <a href="/logout">Logout</a>
                </div>
            </div>
        </body>
        </html>
    ''', username=username, role=role, user_id=user_id)

@app.route('/profile')
def profile():
    # IDOR Vulnerability: No authorization check
    user_id = request.args.get('id', type=int)
    
    if user_id in user_data:
        data = user_data[user_id]
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Profile</title>
                <style>
                    body { font-family: Arial; margin: 40px; background: #f0f0f0; }
                    .container { background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: auto; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>User Profile</h1>
                    <p><strong>Name:</strong> {{ name }}</p>
                    <p><strong>Email:</strong> {{ email }}</p>
                    <p><strong>Secret Data:</strong> {{ secret }}</p>
                    <p class="warning" style="color: red;">⚠️ You can access other users' data by changing the ID parameter!</p>
                    <a href="/dashboard">Back to Dashboard</a>
                </div>
            </body>
            </html>
        ''', name=data['name'], email=data['email'], secret=data['secret'])
    
    return 'User not found'

@app.route('/api/user/<int:user_id>')
def api_user(user_id):
    # IDOR Vulnerability in API
    if user_id in user_data:
        return {
            'success': True,
            'user_id': user_id,
            'data': user_data[user_id]
        }
    return {'success': False, 'error': 'User not found'}

@app.route('/admin')
def admin():
    # Vulnerable: Weak authorization check
    role = session.get('role', '')
    
    # Can be bypassed by manipulating session
    if role != 'admin':
        return 'Access Denied! <a href="/dashboard">Back</a>'
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Panel</title>
            <style>
                body { font-family: Arial; margin: 40px; background: #f0f0f0; }
                .container { background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: auto; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔧 Admin Panel</h1>
                <p>You have administrative access!</p>
                <div style="margin-top: 20px;">
                    <h3>All Users:</h3>
                    {% for uid, data in users.items() %}
                    <p>ID: {{ uid }} - {{ data.name }} ({{ data.email }})</p>
                    {% endfor %}
                </div>
                <a href="/dashboard">Back to Dashboard</a>
            </div>
        </body>
        </html>
    ''', users=user_data)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=True)
