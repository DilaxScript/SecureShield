#!/bin/bash
echo "🔍 SecureShield Health Check"
echo "============================"

# Check Backend
echo -n "Backend API: "
curl -s http://localhost:8000/api/health >/dev/null && echo "✅ Running" || echo "❌ Not running"

# Check Web UI
echo -n "Web UI: "
curl -s http://localhost:8000 >/dev/null && echo "✅ Running" || echo "❌ Not running"

echo "============================"
