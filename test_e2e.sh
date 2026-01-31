#!/bin/bash
# End-to-End Test Script for Docker Hosted LLM

# Configuration
AUTH_URL="http://localhost:5001"
API_URL="http://localhost:5002"
ADMIN_USER="elmo.visuri@gapps.fi" # Default from .env.example
ADMIN_PASS="pomo"              # Default from .env.example

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "🧪 Starting E2E Tests..."

# 1. Health Check
echo -n "Checking API Health... "
HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/health")
if [ "$HEALTH_STATUS" == "200" ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED (Status: $HEALTH_STATUS)${NC}"
    echo "Make sure the stack is running: docker-compose up -d"
    exit 1
fi

# 2. Authentication
echo -n "Authenticating Admin... "
TOKEN_RESPONSE=$(curl -s -X POST "$AUTH_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$ADMIN_USER\", \"password\": \"$ADMIN_PASS\"}")

TOKEN=$(echo $TOKEN_RESPONSE | grep -o '"token": *"[^"]*"' | cut -d'"' -f4)

if [ -n "$TOKEN" ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi

# 3. Inference Test
echo -n "Testing Inference (this may take a moment)... "
echo $TOKEN
INFERENCE_RESPONSE=$(curl -s -X POST "$API_URL/api/generate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Say hello in one word. Use Finnish language.", "stream": true}')

# Check if response contains "response" key or error
if echo "$INFERENCE_RESPONSE" | grep -q "response"; then
    echo -e "${GREEN}OK${NC}"
    echo "LLM Response: $(echo $INFERENCE_RESPONSE | grep -o '"response": *"[^"]*"' | cut -d'"' -f4)"
else
    echo -e "${RED}FAILED${NC}"
    echo "Response: $INFERENCE_RESPONSE"
    exit 1
fi

echo -e "\n✅ All tests passed!"
