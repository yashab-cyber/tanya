# 🏗️ Tanya VAPT System - Technical Architecture

## System Overview

Tanya is a microservices-based AI-powered VAPT system built with modern cloud-native technologies.

## Architecture Layers

### 1. Presentation Layer (Frontend)
- **Technology**: React 18 + Vite + TailwindCSS
- **Purpose**: User interface for scan management and results visualization
- **Key Features**:
  - Real-time scan status updates
  - Interactive vulnerability dashboards
  - Responsive design
  - REST API integration

### 2. Application Layer (Backend)
- **Technology**: FastAPI (Python 3.11+)
- **Purpose**: Core business logic and API endpoints
- **Components**:
  - RESTful API endpoints
  - Request validation (Pydantic)
  - Authentication & Authorization (JWT)
  - Database ORM (SQLAlchemy)

### 3. AI Agent Layer
- **Technology**: Anthropic Claude API + Custom Agents
- **Purpose**: Intelligent test planning and analysis
- **Agents**:
  - **Planning Agent**: Generates test strategies
  - **Execution Agent**: Runs vulnerability tests
  - **Analysis Agent**: Confirms vulnerabilities
  - **Self-Healing Agent**: Adapts to UI changes

### 4. Browser Automation Layer
- **Technology**: Playwright + Computer Use API
- **Purpose**: Automated browser interaction
- **Capabilities**:
  - Headless browser control
  - Screenshot capture
  - HAR file recording
  - Form interaction
  - Cookie management

### 5. Scanning Engine Layer
- **Components**:
  - **Crawler**: URL discovery and mapping
  - **API Extractor**: Endpoint identification
  - **JS Analyzer**: JavaScript file analysis
  - **Parameter Extractor**: Form and parameter discovery

### 6. VAPT Testing Layer
- **Test Modules**:
  - SQL Injection Tester
  - XSS Tester
  - CSRF Tester
  - Authentication Bypass Tester
  - IDOR Tester
  - (Extensible for more)

### 7. Task Queue Layer
- **Technology**: Celery + Redis
- **Purpose**: Asynchronous task processing
- **Tasks**:
  - Full scan execution
  - Report generation
  - Scheduled scans

### 8. Data Layer
- **Primary Database**: PostgreSQL
- **Cache/Queue**: Redis
- **File Storage**: Local filesystem (configurable for S3)

## Data Flow

### Complete Scan Flow

```
User Request → Frontend → Backend API → Celery Task
                                            ↓
                                    Browser Manager
                                            ↓
                                    Crawler Engine
                                            ↓
                                    API Extractor
                                            ↓
                                    JS Analyzer
                                            ↓
                                    Parameter Extractor
                                            ↓
                                    AI Planning Agent
                                            ↓
                                    VAPT Test Orchestrator
                                            ↓
                                    AI Analysis Agent
                                            ↓
                                    Database (Results)
                                            ↓
                                    Frontend (Display)
```

## Component Details

### Backend Components

#### 1. FastAPI Application (`app/main.py`)
- Application initialization
- Middleware configuration (CORS, etc.)
- Router registration
- Global exception handling
- Lifespan management

#### 2. Database Models (`app/models/`)
- **Scan**: Stores scan metadata and results
- **TestResult**: Individual vulnerability findings
- **Report**: Generated report metadata
- **User**: User authentication

#### 3. API Endpoints (`app/api/v1/`)
- **Scans API**: CRUD operations for scans
- **Tests API**: Vulnerability results
- **Reports API**: Report generation
- **Auth API**: User authentication

#### 4. AI Agents (`app/agents/`)
- **ClaudeService**: Anthropic API integration
- **AgentOrchestrator**: Coordinates all agents
- **BrowserManager**: Playwright wrapper

#### 5. Scanners (`app/scanners/`)
- **ScanOrchestrator**: Main scanning workflow
- **CrawlerEngine**: Website crawling
- **APIExtractor**: API discovery
- **JSAnalyzer**: JavaScript analysis
- **ParameterExtractor**: Parameter discovery

#### 6. Testers (`app/testers/`)
- **VAPTTestOrchestrator**: Test coordination
- Individual testers for each vulnerability type

#### 7. Tasks (`app/tasks/`)
- **run_full_scan**: Celery task for scanning
- **generate_report**: Report generation task

### Frontend Components

#### 1. Main Application (`App.jsx`)
- Routing configuration
- Layout and navigation
- Global state management

#### 2. Pages
- **Dashboard**: Scan list and statistics
- **NewScan**: Create new scan form
- **ScanDetail**: Detailed scan results

#### 3. API Client (`api/client.js`)
- Axios-based HTTP client
- API endpoint wrappers
- Authentication handling

## Database Schema

### Scans Table
```sql
- id (Primary Key)
- target_url
- username (encrypted)
- password (encrypted)
- status (enum: pending, running, completed, failed)
- urls_discovered (JSON)
- apis_discovered (JSON)
- js_files_discovered (JSON)
- parameters_discovered (JSON)
- total_urls, total_apis, total_js_files, total_parameters
- har_file_path
- context_data (JSON)
- error_message
- created_at, updated_at, started_at, completed_at
```

### TestResults Table
```sql
- id (Primary Key)
- scan_id (Foreign Key)
- test_type
- test_name
- target_url
- is_vulnerable (boolean)
- severity (enum: critical, high, medium, low, info)
- payload
- request_data (JSON)
- response_data (JSON)
- evidence
- screenshot_path
- remediation
- cve_references (JSON)
- created_at
```

### Reports Table
```sql
- id (Primary Key)
- scan_id (Foreign Key)
- report_type (pdf, html, json)
- file_path
- total_vulnerabilities
- critical_count, high_count, medium_count, low_count, info_count
- created_at
```

### Users Table
```sql
- id (Primary Key)
- email (unique)
- username (unique)
- hashed_password
- full_name
- is_active
- is_superuser
- created_at, updated_at, last_login
```

## Security Architecture

### Authentication Flow
1. User registers/logs in
2. Backend generates JWT token
3. Token stored in localStorage
4. Token sent in Authorization header
5. Backend validates token on each request

### Data Security
- Passwords: bcrypt hashing
- API Keys: Environment variables
- Secrets: Encrypted in database
- CORS: Configurable origins
- Input Validation: Pydantic schemas

### Network Security
- Docker network isolation
- No direct database access
- Rate limiting on API
- HTTPS in production

## Scalability Considerations

### Horizontal Scaling
- **Backend**: Multiple Uvicorn workers
- **Celery**: Multiple worker instances
- **Database**: Read replicas
- **Redis**: Redis Cluster

### Vertical Scaling
- Configurable worker concurrency
- Database connection pooling
- Redis connection pooling
- Browser instance management

## Monitoring & Observability

### Metrics
- Celery Flower dashboard
- Database query performance
- API response times
- Task queue length

### Logging
- Structured JSON logging
- Audit trail for all actions
- Error tracking
- Debug mode toggle

### Health Checks
- Database connectivity
- Redis connectivity
- Celery worker status
- API endpoint health

## Deployment Architecture

### Development
```
Docker Compose → All services on single host
```

### Production
```
Load Balancer
    ↓
Frontend (CDN/Nginx)
    ↓
API Gateway
    ↓
Backend Instances (Auto-scaling)
    ↓
Database (RDS/Managed PostgreSQL)
    ↓
Redis (ElastiCache/Managed Redis)
    ↓
Celery Workers (Auto-scaling)
```

## Technology Stack Summary

| Layer | Technology | Purpose |
|-------|------------|---------|
| Frontend | React 18 + Vite | UI Framework |
| Styling | TailwindCSS | CSS Framework |
| Backend | FastAPI | Web Framework |
| Database | PostgreSQL | Primary Database |
| Cache | Redis | Caching & Queue |
| Task Queue | Celery | Background Tasks |
| Browser | Playwright | Automation |
| AI | Anthropic Claude | Intelligence |
| Container | Docker | Containerization |
| Orchestration | Docker Compose | Service Management |

## API Design Principles

### RESTful Standards
- Resource-based URLs
- HTTP verbs (GET, POST, PUT, DELETE)
- Status codes (200, 201, 404, 500)
- JSON responses

### Versioning
- URL versioning (/api/v1/)
- Backward compatibility
- Deprecation notices

### Pagination
- Offset-based pagination
- Configurable page size
- Total count in response

### Error Handling
- Consistent error format
- Detailed error messages
- Error codes
- Stack traces (dev only)

## Performance Optimizations

### Backend
- Database connection pooling
- Query optimization
- Redis caching
- Async I/O (asyncio)

### Frontend
- Code splitting
- Lazy loading
- React Query caching
- Debounced API calls

### Browser Automation
- Headless mode
- Viewport optimization
- Parallel execution
- Resource blocking

## Future Enhancements

### Planned Features
- [ ] Continuous scanning scheduler
- [ ] API fuzzing
- [ ] Mobile app testing
- [ ] GraphQL support
- [ ] ML-based anomaly detection
- [ ] Custom test scripts
- [ ] Multi-tenant support
- [ ] SSO integration
- [ ] Webhook notifications
- [ ] Export to JIRA/GitHub

### Scalability Improvements
- [ ] Kubernetes deployment
- [ ] Microservices architecture
- [ ] Message queue (RabbitMQ)
- [ ] Object storage (S3)
- [ ] CDN integration

---

**Architecture designed for**: Performance, Scalability, Security, Maintainability
