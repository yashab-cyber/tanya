# 🚀 Tanya VAPT - Quick Start Guide

## Prerequisites Checklist

- [ ] Docker installed and running
- [ ] Docker Compose installed
- [ ] Anthropic API key ready
- [ ] Port 3000, 8000, 5432, 6379, 5555 available

## Step 1: Configure Your API Key

Edit the `.env` file and add your Anthropic API key:

```bash
ANTHROPIC_API_KEY=sk-ant-api03-your-actual-key-here
```

## Step 2: Start the System

```bash
./start.sh
```

This will:
- Build all Docker containers
- Start PostgreSQL, Redis, Backend, Frontend, Celery
- Initialize the database
- Run health checks

Expected output:
```
✅ PostgreSQL is running
✅ Redis is running
✅ Backend is running
✅ Frontend is running
✅ Celery Worker is running

✨ Tanya VAPT System is ready!
```

## Step 3: Access the Application

Open your browser and navigate to:
- **Frontend**: http://localhost:3000
- **API Docs**: http://localhost:8000/api/docs

## Step 4: Run Your First Scan

1. Click "New Scan" in the dashboard
2. Enter a target URL (e.g., `https://example.com`)
3. (Optional) Add authentication credentials
4. Click "Start Scan"
5. Watch as the AI agents analyze your target!

## What Happens During a Scan?

1. **Crawling** (1-2 min)
   - Discovers all URLs
   - Maps the application structure

2. **API Discovery** (30 sec - 1 min)
   - Extracts API endpoints from HAR files
   - Analyzes JavaScript files

3. **Parameter Extraction** (30 sec)
   - Finds all form inputs
   - Identifies URL parameters

4. **AI Planning** (1 min)
   - Claude analyzes the target
   - Generates test strategy

5. **VAPT Testing** (5-10 min)
   - Tests for SQL Injection
   - Tests for XSS
   - Tests for CSRF
   - Tests for Auth Bypass
   - Tests for IDOR

6. **AI Analysis** (2-3 min)
   - Confirms vulnerabilities
   - Filters false positives
   - Generates remediation advice

**Total Time**: 10-20 minutes depending on target size

## Viewing Results

Results appear in real-time on the scan detail page:
- Live status updates
- URL/API discovery counts
- Vulnerability findings by severity
- Detailed evidence and payloads

## Common Commands

### View Logs
```bash
# All services
./logs.sh

# Specific service
./logs.sh backend
./logs.sh celery-worker
```

### Stop the System
```bash
./stop.sh
```

### Restart
```bash
./stop.sh && ./start.sh
```

### Check Service Status
```bash
docker-compose ps
```

## Troubleshooting

### Services Won't Start

**Check if ports are in use:**
```bash
lsof -i :3000  # Frontend
lsof -i :8000  # Backend
lsof -i :5432  # PostgreSQL
lsof -i :6379  # Redis
```

**Solution:** Stop conflicting services or change ports in `.env`

### Backend Errors

**Check backend logs:**
```bash
./logs.sh backend
```

**Common issues:**
- Missing ANTHROPIC_API_KEY
- Database connection failed
- Redis not accessible

### Frontend Not Loading

**Check frontend logs:**
```bash
./logs.sh frontend
```

**Try rebuilding:**
```bash
docker-compose down
docker-compose up -d --build frontend
```

### Celery Worker Not Processing

**Check worker logs:**
```bash
./logs.sh celery-worker
```

**Verify Redis connection:**
```bash
docker-compose exec redis redis-cli ping
# Should return: PONG
```

## Production Deployment

### Security Checklist

- [ ] Change SECRET_KEY and JWT_SECRET_KEY
- [ ] Update POSTGRES_PASSWORD
- [ ] Set strong passwords for all services
- [ ] Update CORS_ORIGINS to your domain
- [ ] Enable HTTPS/SSL
- [ ] Set DEBUG=false
- [ ] Configure firewall rules
- [ ] Set up backup strategy

### Environment Variables for Production

```bash
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=warning
CORS_ORIGINS=https://yourdomain.com
```

## Getting Help

- **API Documentation**: http://localhost:8000/api/docs
- **GitHub Issues**: https://github.com/yashab-cyber/tanya/issues
- **Logs**: Use `./logs.sh` to debug issues

## Next Steps

1. ✅ Complete your first scan
2. 📊 Explore the vulnerability reports
3. 🔧 Customize test parameters in `.env`
4. 🤖 Learn about AI agent capabilities
5. 📖 Read the full documentation

---

Happy Testing! 🛡️
