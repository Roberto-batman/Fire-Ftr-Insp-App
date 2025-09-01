# Fire Truck Inspection App - Quick Start Commands
# Run these commands in your terminal to get started immediately

# ===========================================
# STEP 1: VIRTUAL ENVIRONMENT SETUP (Mac)
# ===========================================

# Navigate to your projects folder
cd ~/Documents/Projects  # or wherever you keep projects

# Create project directory
mkdir fire-inspection-app
cd fire-inspection-app

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# You should see (venv) in your terminal prompt now
# If activation worked, this command will show the venv path:
which python

# ===========================================
# STEP 2: CREATE PROJECT STRUCTURE
# ===========================================

# Create all directories
mkdir -p templates/{auth,admin} static/{css,js,images} tests instance

# Create main Python files
touch app.py config.py models.py routes.py forms.py

# Create HTML templates
touch templates/base.html templates/index.html templates/scan.html templates/inspection.html
touch templates/auth/login.html 
touch templates/admin/dashboard.html templates/admin/qr_code.html

# Create static files
touch static/css/style.css static/js/qr-scanner.js

# Create configuration files
touch requirements.txt .env .env.example .gitignore README.md

# Create test files
touch tests/__init__.py tests/test_app.py

# ===========================================
# STEP 3: CREATE REQUIREMENTS.TXT
# ===========================================

cat > requirements.txt << 'EOF'
Flask==2.3.3
Flask-SQLAlchemy==3.0.5
Flask-Login==0.6.3
Flask-WTF==1.1.1
WTForms==3.0.1
qrcode[pil]==7.4.2
Pillow==10.0.1
pyodbc==4.0.39
python-dotenv==1.0.0
Werkzeug==2.3.7
pytest==7.4.2
pytest-cov==4.1.0
EOF

# ===========================================
# STEP 4: INSTALL DEPENDENCIES
# ===========================================

# Upgrade pip first
pip install --upgrade pip

# Install all required packages
pip install -r requirements.txt

# Verify installation
pip list

# ===========================================
# STEP 5: CREATE ENVIRONMENT VARIABLES
# ===========================================

cat > .env.example << 'EOF'
# Database Configuration
DATABASE_URL=sqlite:///fire_inspection.db
SECRET_KEY=your-secret-key-here-change-in-production

# Azure Configuration (for production)
AZURE_SQL_CONNECTION_STRING=your_azure_connection_string_here

# Development Settings
FLASK_ENV=development
FLASK_DEBUG=True
EOF

# Copy example to actual .env file
cp .env.example .env

# ===========================================
# STEP 6: CREATE .GITIGNORE
# ===========================================

cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
pip-wheel-metadata/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Virtual Environment
venv/
env/
ENV/

# Environment Variables
.env
.env.local
.env.production

# VSCode
.vscode/

# MacOS
.DS_Store

# Database
*.db
*.sqlite3

# Instance folder
instance/

# Logs
*.log

# Azure
.azure/

# Testing
.pytest_cache/
.coverage
htmlcov/
EOF

# ===========================================
# STEP 7: INITIALIZE GIT REPOSITORY
# ===========================================

git init
git add .
git commit -m "feat: initial project structure

- Set up Flask application architecture
- Add virtual environment and dependencies
- Include professional .gitignore and documentation
- Ready for development with security best practices"

# ===========================================
# STEP 8: VERIFY SETUP
# ===========================================

echo "=== SETUP VERIFICATION ==="
echo "Virtual environment active: $(which python)"
echo "Project structure created:"
ls -la

echo ""
echo "=== NEXT STEPS ==="
echo "1. Copy the Flask code from the artifacts into your files"
echo "2. Run: python app.py"
echo "3. Open: http://localhost:5000"
echo "4. Login with: admin/admin123"

echo ""
echo "=== REMEMBER FOR FUTURE SESSIONS ==="
echo "To activate virtual environment:"
echo "cd ~/Documents/Projects/fire-inspection-app"
echo "source venv/bin/activate"

echo ""
echo "To deactivate virtual environment when done:"
echo "deactivate"

# ===========================================
# STEP 9: QUICK TEST COMMANDS
# ===========================================

# Test Flask installation
python -c "import flask; print(f'Flask version: {flask.__version__}')"

# Test QR code library
python -c "import qrcode; print('QR code library installed successfully')"

# Test database library
python -c "import sqlalchemy; print('SQLAlchemy installed successfully')"

echo ""
echo "🎉 Setup complete! Your fire inspection app is ready for development."
echo ""
echo "📝 TODO:"
echo "1. Copy code from artifacts to your files"
echo "2. Test the application locally"  
echo "3. Set up GitHub repository"
echo "4. Deploy to Azure when ready"

# ===========================================
# STEP 10: HELPFUL REMINDERS
# ===========================================

echo ""
echo "💡 HELPFUL VSCode TIPS:"
echo "- Open project: code ."
echo "- Select Python interpreter: Cmd+Shift+P > 'Python: Select Interpreter' > Choose venv/bin/python"
echo "- Install Python extension if not already installed"

echo ""
echo "🔧 DEVELOPMENT WORKFLOW:"
echo "1. Always activate venv first: source venv/bin/activate"
echo "2. Make changes to your code"
echo "3. Test locally: python app.py"
echo "4. Commit changes: git add . && git commit -m 'your message'"
echo "5. Push to GitHub when ready"