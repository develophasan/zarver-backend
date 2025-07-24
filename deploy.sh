#!/bin/bash

echo "🚀 ZARVER Backend Repository Setup"
echo "=================================="

# Current directory check
if [ ! -f "server.py" ]; then
    echo "❌ server.py not found! Run this script from backend directory."
    exit 1
fi

echo "📁 Backend files:"
ls -la

echo ""
echo "✅ Backend repository is ready!"
echo ""
echo "📋 Next steps:"
echo "1. Create new GitHub repository (e.g., 'zarver-backend')"
echo "2. Git init and push:"
echo "   git init"
echo "   git add ."
echo "   git commit -m 'Initial backend commit'"
echo "   git branch -M main"
echo "   git remote add origin https://github.com/username/zarver-backend.git"
echo "   git push -u origin main"
echo ""
echo "3. Deploy to Railway:"
echo "   - Go to railway.app"
echo "   - 'New Project' → 'Deploy from GitHub repo'"
echo "   - Select your new backend repository"
echo "   - Add environment variables (see README.md)"
echo ""
echo "🔧 Required environment variables:"
echo "   MONGO_URL, GEMINI_API_KEY, JWT_SECRET"
echo "   ADMIN_USERNAME, ADMIN_PASSWORD"