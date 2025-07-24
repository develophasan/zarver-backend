#!/bin/bash

echo "🚀 Starting ZARVER Backend API..."
echo "================================="

# Environment check
if [ -z "$MONGO_URL" ]; then
    echo "⚠️  MONGO_URL not set, using default"
fi

if [ -z "$GEMINI_API_KEY" ]; then
    echo "⚠️  GEMINI_API_KEY not set"
fi

# Start the server
echo "Starting FastAPI server on port ${PORT:-8001}..."
python server.py