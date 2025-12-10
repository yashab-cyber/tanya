# Test Target Applications

This directory contains deliberately vulnerable web applications for testing the Tanya VAPT security scanner.

## ⚠️ WARNING
**These applications contain intentional security vulnerabilities. DO NOT deploy them in production or expose them to the internet!**

## Test Applications

### 1. SQL Injection App (Port 5001)
- **URL:** http://localhost:5001
- **Vulnerabilities:**
  - SQL Injection in login form
  - SQL Injection in search functionality
- **Test Credentials:**
  - admin / admin123
  - user1 / pass123
  - demo / demo456
- **Test Payloads:**
  - `admin' OR '1'='1`
  - `' OR 1=1--`
  - `admin'--`

### 2. XSS App (Port 5002)
- **URL:** http://localhost:5002
- **Vulnerabilities:**
  - Reflected XSS in message parameter
  - Stored XSS in comments
  - DOM-based XSS in profile page
- **Test Payloads:**
  - `<script>alert('XSS')</script>`
  - `<img src=x onerror=alert('XSS')>`
  - `<svg onload=alert('XSS')>`

### 3. Auth Bypass & IDOR App (Port 5003)
- **URL:** http://localhost:5003
- **Vulnerabilities:**
  - Weak authentication
  - Authorization bypass
  - IDOR (Insecure Direct Object Reference)
  - Session manipulation
- **Test Credentials:**
  - admin / admin123 (admin role)
  - user / user123 (user role)
  - guest / guest123 (guest role)
- **Test Scenarios:**
  - Access `/dashboard` without login
  - Access `/api/user/1` to view other users' data
  - Manipulate user_id parameter in profile

## Running the Test Applications

### Start all applications:
```bash
cd test-targets
docker-compose up -d
```

### Check status:
```bash
docker-compose ps
```

### View logs:
```bash
docker-compose logs -f
```

### Stop applications:
```bash
docker-compose down
```

### Rebuild after changes:
```bash
docker-compose up -d --build
```

## Testing with Tanya Scanner

### Test SQL Injection App:
```bash
curl -X POST "http://localhost:8000/api/v1/scans/" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://host.docker.internal:5001",
    "scan_type": "comprehensive"
  }'
```

### Test XSS App:
```bash
curl -X POST "http://localhost:8000/api/v1/scans/" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://host.docker.internal:5002",
    "scan_type": "comprehensive"
  }'
```

### Test Auth Bypass App:
```bash
curl -X POST "http://localhost:8000/api/v1/scans/" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://host.docker.internal:5003",
    "scan_type": "comprehensive",
    "username": "admin",
    "password": "admin123"
  }'
```

## Expected Results

The Tanya scanner should detect:

1. **SQL Injection App:**
   - SQL injection vulnerabilities in login
   - SQL injection in search endpoint
   - Database errors revealing structure

2. **XSS App:**
   - Reflected XSS in parameters
   - Stored XSS in comment system
   - DOM-based XSS vulnerabilities

3. **Auth Bypass App:**
   - IDOR vulnerabilities
   - Weak authentication
   - Authorization bypass issues
   - Session management flaws

## Directory Structure

```
test-targets/
├── docker-compose.yml
├── README.md
├── sql-injection-app/
│   ├── app.py
│   ├── requirements.txt
│   └── Dockerfile
├── xss-app/
│   ├── app.py
│   ├── requirements.txt
│   └── Dockerfile
└── auth-bypass-app/
    ├── app.py
    ├── requirements.txt
    └── Dockerfile
```

## Notes

- These applications are for testing purposes only
- They simulate common real-world vulnerabilities
- Use them to validate the scanner's detection capabilities
- Always run in isolated environments (containers)
- Never expose these applications to the internet
