#!/bin/bash

# Tanya VAPT System - Stop Script

set -e

echo "🛑 Stopping Tanya VAPT System..."

# Stop all services
docker-compose down

# Optional: Remove volumes (uncomment to also remove data)
# docker-compose down -v

echo "✅ All services stopped successfully!"
echo ""
echo "To start again, run: ./start.sh"
echo ""
