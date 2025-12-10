from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT
        )
    ''')
    cursor.execute("DELETE FROM users")
    cursor.execute("INSERT INTO users (username, password, email) VALUES ('admin', 'admin123', 'admin@test.com')")
    cursor.execute("INSERT INTO users (username, password, email) VALUES ('user1', 'pass123', 'user1@test.com')")
    cursor.execute("INSERT INTO users (username, password, email) VALUES ('demo', 'demo456', 'demo@test.com')")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>SQL Injection Test App</title>
            <style>
                body { font-family: Arial; margin: 40px; background: #f0f0f0; }
                .container { background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: auto; }
                input { padding: 10px; margin: 10px 0; width: 100%; box-sizing: border-box; }
                button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }
                button:hover { background: #0056b3; }
                .result { margin-top: 20px; padding: 15px; background: #e9ecef; border-radius: 5px; }
                h1 { color: #333; }
                .warning { color: red; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔓 SQL Injection Vulnerable Login</h1>
                <p class="warning">⚠️ This is a DELIBERATELY VULNERABLE test application for security scanning!</p>
                
                <form action="/login" method="GET">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
                
                <div style="margin-top: 20px;">
                    <h3>Test Credentials:</h3>
                    <p>admin / admin123<br>user1 / pass123<br>demo / demo456</p>
                </div>
                
                <div style="margin-top: 20px;">
                    <h3>SQL Injection Test Payloads:</h3>
                    <code>admin' OR '1'='1</code><br>
                    <code>' OR 1=1--</code><br>
                    <code>admin'--</code>
                </div>
            </div>
        </body>
        </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    
    # VULNERABLE SQL QUERY - DO NOT USE IN PRODUCTION
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Intentionally vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Login Success</title>
                    <style>
                        body { font-family: Arial; margin: 40px; background: #f0f0f0; }
                        .container { background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: auto; }
                        .success { color: green; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1 class="success">✅ Login Successful!</h1>
                        <p>Welcome, {{ username }}!</p>
                        <p>Email: {{ email }}</p>
                        <p>User ID: {{ user_id }}</p>
                        <a href="/">Back to Login</a>
                    </div>
                </body>
                </html>
            ''', username=user[1], email=user[3], user_id=user[0])
        else:
            return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Login Failed</title>
                    <style>
                        body { font-family: Arial; margin: 40px; background: #f0f0f0; }
                        .container { background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: auto; }
                        .error { color: red; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1 class="error">❌ Login Failed</h1>
                        <p>Invalid username or password</p>
                        <a href="/">Back to Login</a>
                    </div>
                </body>
                </html>
            ''')
    except Exception as e:
        conn.close()
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Error</title>
                <style>
                    body { font-family: Arial; margin: 40px; background: #f0f0f0; }
                    .container { background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: auto; }
                    .error { color: red; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1 class="error">⚠️ Database Error</h1>
                    <p>{{ error }}</p>
                    <a href="/">Back to Login</a>
                </div>
            </body>
            </html>
        ''', error=str(e))

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Another vulnerable endpoint
    sql = f"SELECT username, email FROM users WHERE username LIKE '%{query}%'"
    
    try:
        cursor.execute(sql)
        results = cursor.fetchall()
        conn.close()
        
        results_html = '<br>'.join([f"{r[0]} - {r[1]}" for r in results])
        
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>User Search</title>
                <style>
                    body { font-family: Arial; margin: 40px; background: #f0f0f0; }
                    .container { background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: auto; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>User Search</h1>
                    <form action="/search" method="GET">
                        <input type="text" name="q" placeholder="Search username" value="{{ query }}">
                        <button type="submit">Search</button>
                    </form>
                    <div style="margin-top: 20px;">
                        <h3>Results:</h3>
                        <p>{{ results|safe }}</p>
                    </div>
                    <a href="/">Back to Home</a>
                </div>
            </body>
            </html>
        ''', query=query, results=results_html if results_html else 'No results found')
    except Exception as e:
        conn.close()
        return f"Error: {str(e)}"

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=True)
