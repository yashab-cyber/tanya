# 🚀 Deployment Checklist

## Pre-Deployment Checklist

### ✅ Configuration
- [ ] Update `ANTHROPIC_API_KEY` in `.env` with your actual API key
- [ ] Change `SECRET_KEY` to a random 32+ character string
- [ ] Change `JWT_SECRET_KEY` to a random 32+ character string
- [ ] Update `POSTGRES_PASSWORD` to a strong password
- [ ] Set `ENVIRONMENT=production`
- [ ] Set `DEBUG=false`
- [ ] Update `CORS_ORIGINS` to your production domain
- [ ] Review all environment variables in `.env`

### ✅ Security
- [ ] All passwords are strong and unique
- [ ] API keys are not committed to version control
- [ ] CORS is properly configured
- [ ] Authentication is enabled
- [ ] Rate limiting is configured
- [ ] SSL/TLS certificates are ready (for production)

### ✅ Infrastructure
- [ ] Docker is installed and running
- [ ] Docker Compose is installed
- [ ] Required ports are available (3000, 8000, 5432, 6379, 5555)
- [ ] Sufficient disk space for logs and data
- [ ] Sufficient RAM (minimum 4GB recommended)

### ✅ Dependencies
- [ ] All required ports are open in firewall
- [ ] Network connectivity is stable
- [ ] DNS is configured (for production)

## Deployment Steps

### Step 1: Clone and Configure
```bash
# Clone repository
git clone https://github.com/yashab-cyber/tanya.git
cd tanya

# Configure environment
nano .env  # Update all required variables
```

### Step 2: Build and Start
```bash
# Make scripts executable
chmod +x start.sh stop.sh logs.sh

# Start the system
./start.sh
```

### Step 3: Verify Services
```bash
# Check all services are running
docker-compose ps

# Expected output: All services should be "Up" and "healthy"
```

### Step 4: Access Applications
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/api/docs
- Celery Flower: http://localhost:5555

### Step 5: Create First User (Optional)
```bash
# Access backend container
docker-compose exec backend bash

# Create superuser (if needed)
# Or use the registration endpoint via API docs
```

### Step 6: Run Test Scan
1. Navigate to http://localhost:3000
2. Click "New Scan"
3. Enter a test URL
4. Monitor the scan progress
5. Verify results are displayed correctly

## Post-Deployment Verification

### ✅ Service Health
- [ ] All Docker containers are running
- [ ] PostgreSQL is accepting connections
- [ ] Redis is responding to pings
- [ ] Backend API is accessible
- [ ] Frontend is loading
- [ ] Celery workers are processing tasks

### ✅ Functionality Tests
- [ ] Can create new scan
- [ ] Scan starts successfully
- [ ] Crawler discovers URLs
- [ ] API endpoints are extracted
- [ ] VAPT tests execute
- [ ] Results are stored in database
- [ ] Frontend displays results
- [ ] Can view vulnerability details

### ✅ Performance
- [ ] API response times < 200ms (simple queries)
- [ ] Frontend loads < 2s
- [ ] Scan completes in reasonable time (10-20 min for medium site)
- [ ] No memory leaks observed
- [ ] CPU usage is acceptable

### ✅ Logs & Monitoring
- [ ] Logs are being written
- [ ] No critical errors in logs
- [ ] Celery Flower is accessible
- [ ] Tasks are being queued and processed

## Production Hardening

### Security Enhancements
```bash
# In .env, set:
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=warning

# Enable HTTPS (use reverse proxy like Nginx)
# Configure firewall rules
# Set up SSL certificates
# Enable rate limiting
```

### Backup Strategy
```bash
# Database backups
docker-compose exec postgres pg_dump -U $POSTGRES_USER $POSTGRES_DB > backup.sql

# Volume backups
docker run --rm -v tanya_postgres_data:/data -v $(pwd):/backup ubuntu tar cvf /backup/postgres_backup.tar /data
```

### Monitoring Setup
```bash
# Set up log rotation
# Configure alert notifications
# Set up uptime monitoring
# Configure performance monitoring
```

## Scaling Considerations

### Horizontal Scaling
```yaml
# In docker-compose.yml, increase replicas:
celery-worker:
  deploy:
    replicas: 3  # Run 3 worker instances

backend:
  deploy:
    replicas: 2  # Run 2 API instances
```

### Resource Limits
```yaml
# Add resource limits in docker-compose.yml:
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 4G
    reservations:
      cpus: '1'
      memory: 2G
```

## Troubleshooting

### Services Won't Start
```bash
# Check logs
./logs.sh

# Check specific service
./logs.sh backend

# Rebuild containers
docker-compose down
docker-compose up -d --build
```

### Database Connection Issues
```bash
# Check PostgreSQL logs
./logs.sh postgres

# Test connection
docker-compose exec backend python -c "from app.core.database import engine; print('Connected!')"
```

### Celery Not Processing
```bash
# Check worker logs
./logs.sh celery-worker

# Check Redis connection
docker-compose exec redis redis-cli ping
```

### Frontend Not Loading
```bash
# Check frontend logs
./logs.sh frontend

# Rebuild frontend
docker-compose up -d --build frontend
```

## Maintenance

### Regular Tasks
- [ ] Weekly: Review logs for errors
- [ ] Weekly: Check disk space
- [ ] Monthly: Update dependencies
- [ ] Monthly: Review and rotate logs
- [ ] Quarterly: Security audit
- [ ] Quarterly: Performance optimization

### Updates
```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
./stop.sh
./start.sh
```

### Backup Schedule
- Database: Daily automated backups
- Volumes: Weekly full backups
- Configurations: Version controlled in Git
- Reports: Backup to external storage

## Emergency Procedures

### System Failure
1. Check logs: `./logs.sh`
2. Restart services: `./stop.sh && ./start.sh`
3. If persistent, check Docker logs: `docker-compose logs`
4. Restore from backup if needed

### Data Recovery
```bash
# Restore database from backup
docker-compose exec -T postgres psql -U $POSTGRES_USER $POSTGRES_DB < backup.sql
```

### Rollback Deployment
```bash
# Checkout previous version
git checkout <previous-commit>

# Rebuild and restart
docker-compose down
docker-compose up -d --build
```

## Success Criteria

✅ All services running and healthy
✅ Can create and complete scans successfully
✅ Results displayed correctly in frontend
✅ No critical errors in logs
✅ Response times within acceptable limits
✅ Security configurations verified
✅ Backups configured and tested
✅ Monitoring in place

## Support

If you encounter issues:
1. Check logs: `./logs.sh`
2. Review documentation: README.md, QUICKSTART.md
3. Check API docs: http://localhost:8000/api/docs
4. Create GitHub issue with logs and error details

---

**Deployment Status**: Ready for Production ✅

*Last Updated: December 1, 2025*
