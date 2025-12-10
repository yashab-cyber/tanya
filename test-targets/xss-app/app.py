from flask import Flask, request, render_template_string, make_response, redirect, url_for
import sqlite3

app = Flask(__name__)

# Simple in-memory storage for comments
comments = [
    {"user": "Alice", "comment": "Great website!"},
    {"user": "Bob", "comment": "Nice work!"}
]

@app.route('/')
def index():
    # Get comment from URL parameter (reflected XSS)
    message = request.args.get('msg', '')
    
    # Build comments HTML (stored XSS vulnerability)
    comments_html = ""
    for c in comments:
        # Vulnerable: No HTML escaping
        comments_html += f'<div class="comment"><strong>{c["user"]}:</strong> {c["comment"]}</div>'
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Vulnerable App</title>
            <style>
                body { font-family: Arial; margin: 40px; background: #f0f0f0; }
                .container { background: white; padding: 30px; border-radius: 10px; max-width: 800px; margin: auto; }
                input, textarea { padding: 10px; margin: 10px 0; width: 100%; box-sizing: border-box; }
                button { padding: 10px 20px; background: #28a745; color: white; border: none; cursor: pointer; }
                button:hover { background: #218838; }
                .comment { margin: 10px 0; padding: 10px; background: #f8f9fa; border-left: 3px solid #007bff; }
                .warning { color: red; font-size: 12px; margin: 10px 0; }
                h1 { color: #333; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>💬 XSS Vulnerable Comment System</h1>
                <p class="warning">⚠️ This is a DELIBERATELY VULNERABLE test application!</p>
                
                <!-- Reflected XSS -->
                {% if msg %}
                <div style="background: #d4edda; padding: 15px; margin: 10px 0; border-radius: 5px;">
                    Message: {{ msg|safe }}
                </div>
                {% endif %}
                
                <!-- Comment form for stored XSS -->
                <h2>Post a Comment</h2>
                <form action="/comment" method="POST">
                    <input type="text" name="user" placeholder="Your name" required>
                    <textarea name="comment" placeholder="Your comment" rows="4" required></textarea>
                    <button type="submit">Post Comment</button>
                </form>
                
                <!-- Display comments (Stored XSS) -->
                <h2>Comments</h2>
                <div id="comments">
                    {{ comments|safe }}
                </div>
                
                <!-- Search form (Reflected XSS) -->
                <h2>Search Comments</h2>
                <form action="/search" method="GET">
                    <input type="text" name="q" placeholder="Search..." value="{{ search_query }}">
                    <button type="submit">Search</button>
                </form>
                
                <div style="margin-top: 30px; border-top: 1px solid #ddd; padding-top: 20px;">
                    <h3>XSS Test Payloads:</h3>
                    <p><strong>Reflected XSS:</strong></p>
                    <code>?msg=&lt;script&gt;alert('XSS')&lt;/script&gt;</code><br>
                    <code>?msg=&lt;img src=x onerror=alert('XSS')&gt;</code><br>
                    <code>?msg=&lt;svg onload=alert('XSS')&gt;</code>
                    
                    <p><strong>Stored XSS (in comment):</strong></p>
                    <code>&lt;script&gt;alert('Stored XSS')&lt;/script&gt;</code><br>
                    <code>&lt;img src=x onerror=alert(document.cookie)&gt;</code>
                </div>
            </div>
        </body>
        </html>
    ''', msg=message, comments=comments_html, search_query='')

@app.route('/comment', methods=['POST'])
def add_comment():
    user = request.form.get('user', 'Anonymous')
    comment = request.form.get('comment', '')
    
    # Vulnerable: No sanitization
    comments.append({"user": user, "comment": comment})
    
    return redirect(url_for('index'))

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # Filter comments
    filtered = [c for c in comments if query.lower() in c['comment'].lower() or query.lower() in c['user'].lower()]
    
    results_html = ""
    for c in filtered:
        results_html += f'<div class="comment"><strong>{c["user"]}:</strong> {c["comment"]}</div>'
    
    if not results_html:
        results_html = f'<p>No results found for: {query}</p>'
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Search Results</title>
            <style>
                body { font-family: Arial; margin: 40px; background: #f0f0f0; }
                .container { background: white; padding: 30px; border-radius: 10px; max-width: 800px; margin: auto; }
                .comment { margin: 10px 0; padding: 10px; background: #f8f9fa; border-left: 3px solid #007bff; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Search Results</h1>
                <p>Search query: {{ query|safe }}</p>
                <div>{{ results|safe }}</div>
                <a href="/">Back to Home</a>
            </div>
        </body>
        </html>
    ''', query=query, results=results_html)

@app.route('/profile')
def profile():
    # DOM-based XSS vulnerability
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>User Profile</title>
            <style>
                body { font-family: Arial; margin: 40px; background: #f0f0f0; }
                .container { background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: auto; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>User Profile</h1>
                <div id="profile"></div>
                <a href="/">Back to Home</a>
            </div>
            
            <script>
                // DOM-based XSS vulnerability
                var username = window.location.hash.substring(1);
                if (username) {
                    document.getElementById('profile').innerHTML = '<h2>Welcome, ' + username + '</h2>';
                }
            </script>
        </body>
        </html>
    ''')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
