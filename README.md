# Tanya - AI-Powered VAPT System

🤖 **Advanced Vulnerability Assessment and Penetration Testing powered by Anthropic Claude and AI Agents**

## 🌟 Overview

Tanya is a production-ready, AI-powered browser automation and VAPT (Vulnerability Assessment and Penetration Testing) system that uses Anthropic's Claude with Computer Use API to automatically discover, scan, and test web applications for security vulnerabilities.

### Key Features

✅ **AI-Powered Testing**
- Anthropic Claude integration with Computer Use API
- Multi-agent architecture (Planning, Execution, Analysis, Self-Healing)
- Intelligent test strategy generation
- Automated vulnerability analysis

✅ **Comprehensive Scanning**
- Auto-crawl and deep URL discovery
- API endpoint extraction from HAR files
- JavaScript file analysis
- Parameter and form discovery
- Session and authentication detection

✅ **Browser Automation**
- Playwright-based headless browser
- Computer vision-based interaction
- Screenshot capture for AI analysis
- HAR file recording for network analysis
- Auto-login capability

✅ **Vulnerability Testing**
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Authentication Bypass
- Insecure Direct Object Reference (IDOR)
- And more...

✅ **Modern Tech Stack**
- **Backend**: Python, FastAPI, Playwright, Celery
- **Frontend**: React, TailwindCSS, Vite
- **Database**: PostgreSQL
- **Cache/Queue**: Redis
- **AI**: Anthropic Claude (Sonnet 4)

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   React     │────▶│   FastAPI    │────▶│ PostgreSQL  │
│  Frontend   │     │   Backend    │     │  Database   │
└─────────────┘     └──────────────┘     └─────────────┘
                            │
                    ┌───────┴────────┐
                    │                │
                ┌───▼────┐      ┌───▼────┐
                │ Redis  │      │ Celery │
                │ Cache  │      │ Worker │
                └────────┘      └────────┘
                                     │
                            ┌────────┴─────────┐
                            │                  │
                       ┌────▼─────┐    ┌──────▼──────┐
                       │ AI Agent │    │  Playwright │
                       │  System  │    │   Browser   │
                       └──────────┘    └─────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Anthropic API Key ([Get one here](https://console.anthropic.com/))

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yashab-cyber/tanya.git
cd tanya
```

2. **Configure environment variables**

The `.env` file is already configured. Update these critical values:

```bash
# Required: Add your Anthropic API key
ANTHROPIC_API_KEY=sk-ant-api03-your-actual-key-here

# Update these for production
SECRET_KEY=your-secret-key-change-in-production-min-32-chars
JWT_SECRET_KEY=your-jwt-secret-key-change-in-production-min-32-chars
POSTGRES_PASSWORD=your-strong-database-password
```

3. **Start the application**
```bash
chmod +x start.sh stop.sh logs.sh
./start.sh
```

4. **Access the application**

- **Frontend Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/api/docs
- **Celery Flower**: http://localhost:5555

## 📖 Usage

### Creating a New Scan

1. Navigate to http://localhost:3000
2. Click "New Scan"
3. Enter target URL (e.g., https://example.com)
4. Optionally provide authentication credentials
5. Click "Start Scan"

The system will automatically:
1. Crawl the website and discover all URLs
2. Extract API endpoints from network traffic
3. Analyze JavaScript files for secrets
4. Identify all parameters and forms
5. Run vulnerability tests (SQLi, XSS, CSRF, etc.)
6. Use AI agents to analyze and confirm vulnerabilities
7. Generate detailed reports

### Viewing Results

- **Dashboard**: Real-time scan status and statistics
- **Scan Details**: Comprehensive results with vulnerability breakdown
- **Severity Levels**: Critical, High, Medium, Low, Info
- **Evidence**: Payloads, requests, responses, screenshots

## 🔧 Configuration

### Environment Variables

Key configuration options in `.env`:

```bash
# AI Configuration
ANTHROPIC_MODEL=claude-sonnet-4-20250514
ANTHROPIC_MAX_TOKENS=4096

# Scanning Configuration
MAX_CRAWL_DEPTH=5
MAX_URLS_PER_DOMAIN=10000
CRAWL_DELAY_MS=100

# Testing Configuration
TEST_INTENSITY=medium  # low, medium, high
TEST_PARALLEL_WORKERS=5

# Enable/Disable Tests
ENABLE_SQL_INJECTION_TESTS=true
ENABLE_XSS_TESTS=true
ENABLE_CSRF_TESTS=true
ENABLE_AUTHENTICATION_BYPASS_TESTS=true
```

## 🛠️ Development

### Project Structure

```
tanya/
├── backend/
│   ├── app/
│   │   ├── agents/          # AI agents & browser automation
│   │   ├── api/             # API endpoints
│   │   ├── core/            # Configuration & database
│   │   ├── models/          # Database models
│   │   ├── scanners/        # Scanning engine
│   │   ├── services/        # External services (Claude)
│   │   ├── tasks/           # Celery tasks
│   │   ├── testers/         # VAPT testing modules
│   │   └── main.py          # FastAPI application
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── api/             # API client
│   │   ├── pages/           # React pages
│   │   ├── App.jsx          # Main app component
│   │   └── main.jsx         # Entry point
│   ├── Dockerfile
│   └── package.json
├── docker-compose.yml
├── .env                     # Environment configuration
├── start.sh                 # Startup script
├── stop.sh                  # Stop script
└── README.md
```

### Running in Development Mode

```bash
# Backend only
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend only
cd frontend
npm install
npm run dev

# Celery worker
cd backend
celery -A app.celery_app worker --loglevel=info
```

## 📊 Monitoring

### View Logs

```bash
# All services
./logs.sh

# Specific service
./logs.sh backend
./logs.sh frontend
./logs.sh celery-worker
```

### Celery Monitoring

Access Flower dashboard at http://localhost:5555 to monitor:
- Active tasks
- Task history
- Worker status
- Task statistics

## 🔒 Security Considerations

⚠️ **Important Security Notes:**

1. **API Keys**: Never commit API keys to version control
2. **Passwords**: Use strong passwords in production
3. **Network**: Run scans only on authorized targets
4. **Isolation**: Scans run in isolated Docker containers
5. **Authentication**: Enable authentication for production use

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

This project is licensed under the MIT License.

## 🆘 Support

For issues and questions:
- GitHub Issues: https://github.com/yashab-cyber/tanya/issues
- Documentation: Check `/api/docs` for API reference

## 🙏 Acknowledgments

- **Anthropic** for Claude API and Computer Use
- **Playwright** for browser automation
- **FastAPI** for the amazing web framework
- **React** for the frontend framework

---

**Built with ❤️ by the Tanya Team**

*Powered by Anthropic Claude & AI Agents*
