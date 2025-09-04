# app.py - Fire Truck Inspection System
# Professional Flask application with proper error handling and logging
# Compatible with Flask 3.0 and Azure SQL Database

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import urllib.parse
import qrcode
import io
import base64
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'

# Database Configuration
def get_database_uri():
    """Configure database connection based on environment"""
    try:
        if os.environ.get('WEBSITE_HOSTNAME'):  # Running on Azure
            logger.info("Configuring Azure SQL Database...")
            
            server = os.environ.get('DB_SERVER')
            database = os.environ.get('DB_NAME') 
            username = os.environ.get('DB_USERNAME')
            password = os.environ.get('DB_PASSWORD')
            
            logger.info(f"Server: {server}")
            logger.info(f"Database: {database}")
            logger.info(f"Username: {username}")
            logger.info(f"Password: {'***SET***' if password else 'NOT SET'}")
            
            if not all([server, database, username, password]):
                logger.error("Missing database environment variables - falling back to SQLite")
                return 'sqlite:///fire_inspection.db'
            
            connection_string = (
                f"Driver={{ODBC Driver 18 for SQL Server}};"
                f"Server=tcp:{server},1433;"
                f"Database={database};"
                f"Uid={username};"
                f"Pwd={password};"
                f"Encrypt=yes;"
                f"TrustServerCertificate=no;"
                f"Connection Timeout=30;"
            )
            
            params = urllib.parse.quote_plus(connection_string)
            return f"mssql+pyodbc:///?odbc_connect={params}"
            
        else:
            logger.info("Using SQLite for local development")
            return 'sqlite:///fire_inspection.db'
            
    except Exception as e:
        logger.error(f"Database configuration error: {e}")
        return 'sqlite:///fire_inspection.db'

app.config['SQLALCHEMY_DATABASE_URI'] = get_database_uri()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'

# Database Models
class User(UserMixin, db.Model):
    """User authentication and profile model"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    must_change_password = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        """Hash and set user password"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Equipment(db.Model):
    """Fire equipment and vehicle tracking model"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    equipment_type = db.Column(db.String(50), nullable=False)  # truck, equipment, tool
    serial_number = db.Column(db.String(100))
    location = db.Column(db.String(100))
    qr_code = db.Column(db.String(100), unique=True, nullable=False, index=True)
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Equipment {self.name}>'

class Inspection(db.Model):
    """Equipment inspection records model"""
    id = db.Column(db.Integer, primary_key=True)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    inspection_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)  # passed, failed, pending
    notes = db.Column(db.Text)
    
    # Relationships
    equipment = db.relationship('Equipment', backref=db.backref('inspections', lazy=True))
    user = db.relationship('User', backref=db.backref('inspections', lazy=True))

    def __repr__(self):
        return f'<Inspection {self.equipment.name} - {self.status}>'

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login session management"""
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {e}")
        return None

def initialize_database():
    """Initialize database with default users and equipment"""
    try:
        logger.info("Initializing database...")
        
        # Create all tables
        with app.app_context():
            db.create_all()
            
        # Check if already initialized
        if User.query.filter_by(username='WBrunton_a').first():
            logger.info("Database already initialized")
            return True
        
        logger.info("Creating default users and equipment...")
        
        # Create admin users
        admin1 = User(
            username='WBrunton_a',
            is_admin=True,
            must_change_password=True
        )
        admin1.set_password('TempAdmin123!')
        
        admin2 = User(
            username='HGirard_a',
            is_admin=True,
            must_change_password=True
        )
        admin2.set_password('TempAdmin123!')
        
        # Create regular users  
        user1 = User(
            username='WBrunton',
            is_admin=False,
            must_change_password=True
        )
        user1.set_password('TempUser123!')
        
        user2 = User(
            username='HGirard',
            is_admin=False,
            must_change_password=True
        )
        user2.set_password('TempUser123!')
        
        # Add users
        db.session.add_all([admin1, admin2, user1, user2])
        
        # Create Espanola Fire Department equipment based on Unit 9110
        equipment_data = [
            {'name': 'Unit 9110 - Pumper Truck', 'type': 'truck', 'serial': 'ESP-9110', 'location': 'Bay 1', 'qr': 'ESP9110'},
            {'name': 'Unit 9111 - Rescue Truck', 'type': 'truck', 'serial': 'ESP-9111', 'location': 'Bay 2', 'qr': 'ESP9111'},
            {'name': 'Portable Radio Set A', 'type': 'equipment', 'serial': 'RAD-001', 'location': 'Unit 9110', 'qr': 'RAD001'},
            {'name': 'SCBA Unit 1', 'type': 'equipment', 'serial': 'SCBA-001', 'location': 'Unit 9110', 'qr': 'SCBA001'},
            {'name': 'Fire Hose 50ft', 'type': 'equipment', 'serial': 'HOSE-001', 'location': 'Unit 9110', 'qr': 'HOSE001'},
            {'name': 'Ladder - 24ft Extension', 'type': 'equipment', 'serial': 'LADD-001', 'location': 'Unit 9110', 'qr': 'LADD001'},
            {'name': 'Fire Extinguisher - 20lb', 'type': 'equipment', 'serial': 'EXT-001', 'location': 'Unit 9110', 'qr': 'EXT001'},
        ]
        
        for eq_data in equipment_data:
            equipment = Equipment(
                name=eq_data['name'],
                equipment_type=eq_data['type'],
                serial_number=eq_data['serial'],
                location=eq_data['location'],
                qr_code=eq_data['qr']
            )
            db.session.add(equipment)
        
        # Commit all changes
        db.session.commit()
        logger.info("✅ Database initialized successfully!")
        logger.info("👤 Admin users: WBrunton_a, HGirard_a")
        logger.info("👤 Regular users: WBrunton, HGirard")
        logger.info("🚛 Equipment items added from Espanola Fire Department")
        return True
        
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        db.session.rollback()
        return False

# Routes - Main Application
@app.route('/')
def index():
    """Landing page"""
    try:
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        return f"Application error: {e}", 500

@app.route('/debug')
def debug_info():
    """System diagnostics endpoint"""
    try:
        info = {
            'environment': 'Azure' if os.environ.get('WEBSITE_HOSTNAME') else 'Local',
            'database_uri_preview': app.config['SQLALCHEMY_DATABASE_URI'][:60] + '...',
            'environment_variables': {
                'DB_SERVER': os.environ.get('DB_SERVER', 'NOT SET'),
                'DB_NAME': os.environ.get('DB_NAME', 'NOT SET'), 
                'DB_USERNAME': os.environ.get('DB_USERNAME', 'NOT SET'),
                'DB_PASSWORD': 'SET' if os.environ.get('DB_PASSWORD') else 'NOT SET'
            }
        }
        
        # Test database connectivity
        try:
            with app.app_context():
                db.create_all()
                user_count = User.query.count()
                equipment_count = Equipment.query.count()
                info['database_status'] = 'Connected'
                info['user_count'] = user_count
                info['equipment_count'] = equipment_count
        except Exception as e:
            info['database_status'] = f'Error: {str(e)}'
            info['user_count'] = 0
            info['equipment_count'] = 0
        
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User authentication"""
    try:
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            if not username or not password:
                flash('Please enter both username and password', 'error')
                return render_template('auth/login.html')
            
            user = User.query.filter_by(username=username).first()
            
            if user and user.check_password(password):
                login_user(user)
                user.last_login = datetime.utcnow()
                db.session.commit()
                
                logger.info(f"User {username} logged in successfully")
                
                if user.must_change_password:
                    flash('You must change your password before continuing', 'warning')
                    return redirect(url_for('change_password'))
                
                flash(f'Welcome back, {username}!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                logger.warning(f"Failed login attempt for username: {username}")
                flash('Invalid username or password', 'error')
        
        return render_template('auth/login.html')
    except Exception as e:
        logger.error(f"Error in login route: {e}")
        return f"Login system error: {e}", 500

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    try:
        username = current_user.username
        logout_user()
        logger.info(f"User {username} logged out")
        flash('You have been logged out successfully', 'info')
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Error in logout route: {e}")
        return f"Logout error: {e}", 500

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Password change interface"""
    try:
        if request.method == 'POST':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            # Validate current password
            if not current_user.check_password(current_password):
                flash('Current password is incorrect', 'error')
                return render_template('auth/change_password.html')
            
            # Validate new password
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
                return render_template('auth/change_password.html')
            
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'error')
                return render_template('auth/change_password.html')
            
            # Update password
            current_user.set_password(new_password)
            current_user.must_change_password = False
            db.session.commit()
            
            logger.info(f"Password changed for user {current_user.username}")
            flash('Password changed successfully!', 'success')
            return redirect(url_for('dashboard'))
        
        return render_template('auth/change_password.html')
    except Exception as e:
        logger.error(f"Error in change_password route: {e}")
        return f"Password change error: {e}", 500

# Main Application Routes
@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    try:
        if current_user.must_change_password:
            return redirect(url_for('change_password'))
        
        # Get user statistics
        user_inspections = Inspection.query.filter_by(user_id=current_user.id).order_by(Inspection.inspection_date.desc()).limit(5).all()
        total_equipment = Equipment.query.filter_by(active=True).count()
        
        return render_template('dashboard.html', 
                             recent_inspections=user_inspections,
                             equipment_count=total_equipment)
    except Exception as e:
        logger.error(f"Error in dashboard route: {e}")
        return f"Dashboard error: {e}", 500

@app.route('/scanner')
@login_required
def qr_scanner():
    """QR code scanning interface"""
    try:
        if current_user.must_change_password:
            return redirect(url_for('change_password'))
        return render_template('scanner/qr_scanner.html')
    except Exception as e:
        logger.error(f"Error in qr_scanner route: {e}")
        return f"Scanner error: {e}", 500

@app.route('/equipment/<qr_code>')
@login_required
def equipment_detail(qr_code):
    """Equipment details and inspection history - Demo accessible"""
    try:
        equipment = Equipment.query.filter_by(qr_code=qr_code, active=True).first_or_404()
        recent_inspections = Inspection.query.filter_by(equipment_id=equipment.id).order_by(Inspection.inspection_date.desc()).limit(10).all()
        
        return render_template('equipment/detail.html', 
                             equipment=equipment,
                             recent_inspections=recent_inspections)
    except Exception as e:
        logger.error(f"Error in equipment_detail route: {e}")
        return f"Equipment detail error: {e}", 500

@app.route('/equipment/<int:equipment_id>/inspect', methods=['GET', 'POST'])
@login_required
def inspect_equipment(equipment_id):
    """Equipment inspection form"""
    try:
        if current_user.must_change_password:
            return redirect(url_for('change_password'))
        
        equipment = Equipment.query.get_or_404(equipment_id)
        
        if request.method == 'POST':
            status = request.form.get('status')
            notes = request.form.get('notes', '').strip()
            
            if status not in ['passed', 'failed', 'pending']:
                flash('Invalid inspection status', 'error')
                return render_template('equipment/inspect.html', equipment=equipment)
            
            # Create inspection record
            inspection = Inspection(
                equipment_id=equipment_id,
                user_id=current_user.id,
                status=status,
                notes=notes
            )
            
            db.session.add(inspection)
            db.session.commit()
            
            logger.info(f"Inspection completed by {current_user.username} for {equipment.name}: {status}")
            flash(f'Inspection completed for {equipment.name}', 'success')
            return redirect(url_for('equipment_detail', qr_code=equipment.qr_code))
        
        return render_template('equipment/inspect.html', equipment=equipment)
    except Exception as e:
        logger.error(f"Error in inspect_equipment route: {e}")
        return f"Inspection error: {e}", 500

# Admin Routes
@app.route('/admin')
@login_required
def admin_dashboard():
    """Administrative dashboard"""
    try:
        if not current_user.is_admin:
            flash('Access denied - Administrator privileges required', 'error')
            return redirect(url_for('dashboard'))
        
        if current_user.must_change_password:
            return redirect(url_for('change_password'))
        
        # Admin statistics
        stats = {
            'total_users': User.query.count(),
            'total_equipment': Equipment.query.count(),
            'total_inspections': Inspection.query.count(),
            'recent_inspections': Inspection.query.order_by(Inspection.inspection_date.desc()).limit(10).all()
        }
        
        return render_template('admin/dashboard.html', **stats)
    except Exception as e:
        logger.error(f"Error in admin_dashboard route: {e}")
        return f"Admin dashboard error: {e}", 500

@app.route('/admin/equipment/<int:equipment_id>/qr')
@login_required
def generate_qr_code(equipment_id):
    """Generate QR code for equipment"""
    try:
        if not current_user.is_admin:
            flash('Access denied - Administrator privileges required', 'error')
            return redirect(url_for('dashboard'))
        
        equipment = Equipment.query.get_or_404(equipment_id)
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr_data = f"{request.url_root}equipment/{equipment.qr_code}"
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return render_template('admin/qr_display.html', 
                             equipment=equipment,
                             qr_image=img_str,
                             qr_url=qr_data)
    except Exception as e:
        logger.error(f"Error in generate_qr_code route: {e}")
        return f"QR generation error: {e}", 500

# Initialize database on startup
try:
    with app.app_context():
        success = initialize_database()
        if not success:
            logger.error("Database initialization failed - application may not work correctly")
except Exception as e:
    logger.error(f"Critical error during startup: {e}")

if __name__ == '__main__':
    app.run(debug=True)