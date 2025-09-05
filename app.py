# app.py - Fire Truck Inspection System - Unit 9110 Real Data
# Updated with actual inventory from Espanola Fire Department

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
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

# Database configuration (keeping your existing setup)
def get_database_uri():
    """Configure database connection based on environment"""
    try:
        if os.environ.get('WEBSITE_HOSTNAME'):  # Running on Azure
            server = os.environ.get('DB_SERVER')
            database = os.environ.get('DB_NAME') 
            username = os.environ.get('DB_USERNAME')
            password = os.environ.get('DB_PASSWORD')
            
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
login_manager.login_view = 'login'

# REAL UNIT 9110 INVENTORY DATA (Extracted from Excel)
UNIT_9110_INVENTORY = {
    'UNIT9110_L1': {
        'name': 'Locker 1',
        'truck': 'Unit 9110',
        'description': 'SCBA Storage - Critical breathing equipment for firefighter safety',
        'sections': {
            'main': [
                {'name': 'Locker Light', 'quantity': 1, 'type': 'functional_check', 'critical': True},
                {'name': 'Scott SCBA', 'quantity': 2, 'type': 'equipment', 'critical': True}
            ]
        }
    },
    'UNIT9110_L2': {
        'name': 'Locker 2', 
        'truck': 'Unit 9110',
        'description': 'Hose & Nozzle Equipment - Primary firefighting tools',
        'sections': {
            'main': [
                {'name': 'Locker Light', 'quantity': 1, 'type': 'functional_check', 'critical': True},
                {'name': 'High Vol. 100mm', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': '65mm Pony Hose (Yellow)', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': '38mm Hose Canvas', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': '38mm Hose (Red)', 'quantity': 2, 'type': 'equipment', 'critical': False},
                {'name': 'Rope / Bungee Cords', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': '65X65X65mm WYE', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': 'Turbo Jet Nozzle', 'quantity': 1, 'type': 'equipment', 'critical': True},
                {'name': 'Monitor Extension Pipe', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': '65mm Combo Nozzle', 'quantity': 1, 'type': 'equipment', 'critical': True},
                {'name': 'Stortz to 6" Hydrant Adapters', 'quantity': 2, 'type': 'equipment', 'critical': True},
                {'name': 'Stortz to 65mm Male:Female Adp.', 'quantity': 2, 'type': 'equipment', 'critical': False},
                {'name': '65 to 38mm Adapter (Black)', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': 'Bush Nozzles', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': 'Cellar Nozzler', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': '65mm Double Male/Female', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': '65mm Cap', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': '38x25mmTip & Nozzle', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': '38x12mm Tip', 'quantity': 1, 'type': 'equipment', 'critical': False}
            ],
            'left_door': [
                {'name': 'Hose Spanners', 'quantity': 2, 'type': 'equipment', 'critical': True},
                {'name': 'High Vol. 100mm', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': 'Rubber Mallets', 'quantity': 2, 'type': 'equipment', 'critical': False}
            ],
            'right_door': [
                {'name': 'Spanner Orange Handle', 'quantity': 2, 'type': 'equipment', 'critical': False},
                {'name': 'Hose Spanner', 'quantity': 1, 'type': 'equipment', 'critical': True},
                {'name': 'Combo Hydrant', 'quantity': 1, 'type': 'equipment', 'critical': False}
            ]
        }
    },
    'UNIT9110_L3': {
        'name': 'Locker 3',
        'truck': 'Unit 9110', 
        'description': 'Additional SCBA Bottles - Backup air supply',
        'sections': {
            'main': [
                {'name': 'Locker Light', 'quantity': 1, 'type': 'functional_check', 'critical': True},
                {'name': 'SCBA Bottles (4000psi)', 'quantity': 5, 'type': 'equipment', 'critical': True}
            ]
        }
    },
    'UNIT9110_L4': {
        'name': 'Locker 4',
        'truck': 'Unit 9110',
        'description': 'Fire Extinguishers - Initial suppression equipment',
        'sections': {
            'main': [
                {'name': 'Locker Light', 'quantity': 1, 'type': 'functional_check', 'critical': True},
                {'name': 'Pump Tank', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': 'Pressure Tank', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': 'Extinguisher 20lb ABC', 'quantity': 1, 'type': 'equipment', 'critical': True},
                {'name': 'Extinguisher 10lb ABC', 'quantity': 1, 'type': 'equipment', 'critical': True}
            ]
        }
    },
    'UNIT9110_L11': {
        'name': 'Locker 11',
        'truck': 'Unit 9110',
        'description': 'Command & Communications - Mission critical equipment',
        'sections': {
            'main': [
                {'name': 'Locker Light', 'quantity': 1, 'type': 'functional_check', 'critical': True},
                {'name': 'Honda Generator', 'quantity': 1, 'type': 'equipment', 'critical': True},
                {'name': 'Radios (Green Light On)', 'quantity': 6, 'type': 'equipment', 'critical': True},
                {'name': 'Thermal Imaging Camera', 'quantity': 1, 'type': 'equipment', 'critical': True},
                {'name': 'First Aid Kit', 'quantity': 1, 'type': 'equipment', 'critical': True},
                {'name': 'Fire Extinguisher 5lbs', 'quantity': 1, 'type': 'equipment', 'critical': True},
                {'name': 'Extension Cords & GFI', 'quantity': 1, 'type': 'equipment', 'critical': False},
                {'name': 'Flash Lights', 'quantity': 2, 'type': 'equipment', 'critical': True},
                {'name': 'Naloxone Kit', 'quantity': 1, 'type': 'equipment', 'critical': True}
            ]
        }
    }
}

# Database Models (keeping your existing structure)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Equipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    equipment_type = db.Column(db.String(50), nullable=False)
    serial_number = db.Column(db.String(100))
    location = db.Column(db.String(100))
    qr_code = db.Column(db.String(100), unique=True, nullable=False)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Inspection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    inspection_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # passed, failed, pending
    notes = db.Column(db.Text)
    discrepancies = db.Column(db.Text)  # JSON string of missing/extra items
    completion_percentage = db.Column(db.Float, default=100.0)
    
    equipment = db.relationship('Equipment', backref='inspections')
    user = db.relationship('User', backref='inspections')

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except:
        return None

def create_unit_9110_equipment():
    """Create equipment records for Unit 9110 lockers"""
    try:
        for qr_code, locker_data in UNIT_9110_INVENTORY.items():
            if not Equipment.query.filter_by(qr_code=qr_code).first():
                equipment = Equipment(
                    name=locker_data['name'],
                    equipment_type='locker',
                    location=locker_data['truck'],
                    qr_code=qr_code,
                    serial_number=f"ESP-{qr_code}"
                )
                db.session.add(equipment)
        
        db.session.commit()
        logger.info("✅ Unit 9110 equipment records created")
        return True
    except Exception as e:
        logger.error(f"❌ Error creating Unit 9110 equipment: {e}")
        db.session.rollback()
        return False

def initialize_database():
    """Initialize database with users and equipment"""
    try:
        db.create_all()
        
        # Create users if they don't exist
        if not User.query.filter_by(username='WBrunton_a').first():
            # Admin users
            admin1 = User(username='WBrunton_a', is_admin=True)
            admin1.set_password('TempAdmin123!')
            admin2 = User(username='HGirard_a', is_admin=True)
            admin2.set_password('TempAdmin123!')
            
            # Regular users
            user1 = User(username='WBrunton', is_admin=False)
            user1.set_password('TempUser123!')
            user2 = User(username='HGirard', is_admin=False)
            user2.set_password('TempUser123!')
            
            db.session.add_all([admin1, admin2, user1, user2])
            db.session.commit()
            logger.info("✅ Users created")
        
        # Create Unit 9110 equipment
        create_unit_9110_equipment()
        
        return True
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        return False

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/init-database')
def init_database():
    """Initialize database endpoint"""
    try:
        success = initialize_database()
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Unit 9110 inspection system initialized!',
                'users_created': User.query.count(),
                'equipment_created': Equipment.query.count(),
                'lockers_available': list(UNIT_9110_INVENTORY.keys())
            })
        else:
            return jsonify({'status': 'error', 'message': 'Initialization failed'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/debug')
def debug_info():
    """System diagnostics"""
    try:
        info = {
            'database_status': 'Connected',
            'user_count': User.query.count(),
            'equipment_count': Equipment.query.count(),
            'available_lockers': len(UNIT_9110_INVENTORY),
            'locker_qr_codes': list(UNIT_9110_INVENTORY.keys())
        }
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            if user.must_change_password:
                return redirect(url_for('change_password'))
            
            flash(f'Welcome, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('auth/login.html')

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return render_template('auth/change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('auth/change_password.html')
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('auth/change_password.html')
        
        current_user.set_password(new_password)
        current_user.must_change_password = False
        db.session.commit()
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('auth/change_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.must_change_password:
        return redirect(url_for('change_password'))
    
    # Get recent inspections for current user
    recent_inspections = Inspection.query.filter_by(user_id=current_user.id)\
        .order_by(Inspection.inspection_date.desc()).limit(5).all()
    
    return render_template('dashboard.html',
                         recent_inspections=recent_inspections,
                         equipment_count=len(UNIT_9110_INVENTORY))

@app.route('/scanner')
def qr_scanner():
    """QR scanner - accessible for demo"""
    return render_template('scanner/qr_scanner.html', 
                         available_lockers=UNIT_9110_INVENTORY)

@app.route('/locker/<qr_code>')
def locker_detail(qr_code):
    """Display locker inventory - QR code endpoint"""
    try:
        if qr_code not in UNIT_9110_INVENTORY:
            flash(f'Locker QR code {qr_code} not found', 'error')
            return redirect(url_for('qr_scanner'))
        
        locker_data = UNIT_9110_INVENTORY[qr_code]
        
        # Calculate inventory statistics
        total_items = 0
        critical_items = 0
        functional_checks = 0
        
        for section_name, items in locker_data['sections'].items():
            for item in items:
                total_items += item['quantity']
                if item.get('critical', False):
                    critical_items += item['quantity']
                if item['type'] == 'functional_check':
                    functional_checks += 1
        
        # Get recent inspections for this locker
        equipment = Equipment.query.filter_by(qr_code=qr_code).first()
        recent_inspections = []
        if equipment:
            recent_inspections = Inspection.query.filter_by(equipment_id=equipment.id)\
                .order_by(Inspection.inspection_date.desc()).limit(5).all()
        
        return render_template('locker/detail.html',
                             locker=locker_data,
                             qr_code=qr_code,
                             total_items=total_items,
                             critical_items=critical_items,
                             functional_checks=functional_checks,
                             recent_inspections=recent_inspections)
    
    except Exception as e:
        logger.error(f"Error in locker_detail: {e}")
        flash('Error loading locker details', 'error')
        return redirect(url_for('qr_scanner'))

@app.route('/locker/<qr_code>/inspect', methods=['GET', 'POST'])
@login_required
def inspect_locker(qr_code):
    """Locker inspection form"""
    try:
        if qr_code not in UNIT_9110_INVENTORY:
            flash('Invalid QR code', 'error')
            return redirect(url_for('qr_scanner'))
        
        locker_data = UNIT_9110_INVENTORY[qr_code]
        
        if request.method == 'POST':
            # Process inspection form
            discrepancies = []
            total_expected = 0
            total_found = 0
            
            for section_name, items in locker_data['sections'].items():
                for item in items:
                    expected_qty = item['quantity']
                    found_qty = int(request.form.get(f"{section_name}_{item['name']}_qty", expected_qty))
                    
                    total_expected += expected_qty
                    total_found += found_qty
                    
                    if found_qty != expected_qty:
                        discrepancies.append({
                            'section': section_name,
                            'item': item['name'],
                            'expected': expected_qty,
                            'found': found_qty,
                            'critical': item.get('critical', False)
                        })
            
            # Calculate completion percentage
            completion_percentage = (total_found / total_expected * 100) if total_expected > 0 else 100.0
            
            # Determine overall status
            if completion_percentage == 100:
                status = 'passed'
            elif completion_percentage >= 95:
                status = 'warning'  # Yellow flag
            else:
                status = 'failed'   # Red flag
            
            # Get or create equipment record
            equipment = Equipment.query.filter_by(qr_code=qr_code).first()
            if not equipment:
                equipment = Equipment(
                    name=locker_data['name'],
                    equipment_type='locker',
                    location=locker_data['truck'],
                    qr_code=qr_code
                )
                db.session.add(equipment)
                db.session.flush()
            
            # Create inspection record
            inspection = Inspection(
                equipment_id=equipment.id,
                user_id=current_user.id,
                status=status,
                notes=request.form.get('notes', ''),
                discrepancies=str(discrepancies) if discrepancies else None,
                completion_percentage=completion_percentage
            )
            
            db.session.add(inspection)
            db.session.commit()
            
            # Flash appropriate message
            if status == 'passed':
                flash(f'✅ {locker_data["name"]} inspection completed - All items present', 'success')
            elif status == 'warning':
                flash(f'⚠️ {locker_data["name"]} inspection completed - {completion_percentage:.1f}% complete (Yellow Flag)', 'warning')
            else:
                flash(f'❌ {locker_data["name"]} inspection failed - {completion_percentage:.1f}% complete (Red Flag)', 'error')
            
            return redirect(url_for('locker_detail', qr_code=qr_code))
        
        return render_template('locker/inspect.html', 
                             locker=locker_data, 
                             qr_code=qr_code)
    
    except Exception as e:
        logger.error(f"Error in inspect_locker: {e}")
        flash('Error processing inspection', 'error')
        return redirect(url_for('locker_detail', qr_code=qr_code))

@app.route('/admin')
@login_required
def admin_dashboard():
    """Admin dashboard with inspection overview"""
    if not current_user.is_admin:
        flash('Access denied - Administrator privileges required', 'error')
        return redirect(url_for('dashboard'))
    
    if current_user.must_change_password:
        return redirect(url_for('change_password'))
    
    # Get inspection statistics for past 7 days
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_inspections = Inspection.query.filter(Inspection.inspection_date >= week_ago)\
        .order_by(Inspection.inspection_date.desc()).all()
    
    # Calculate statistics
    total_inspections = len(recent_inspections)
    passed_inspections = len([i for i in recent_inspections if i.status == 'passed'])
    failed_inspections = len([i for i in recent_inspections if i.status == 'failed'])
    warning_inspections = len([i for i in recent_inspections if i.status == 'warning'])
    
    # Get completion rate by locker
    locker_stats = {}
    for inspection in recent_inspections:
        locker_qr = inspection.equipment.qr_code
        if locker_qr not in locker_stats:
            locker_stats[locker_qr] = {
                'name': UNIT_9110_INVENTORY.get(locker_qr, {}).get('name', 'Unknown'),
                'inspections': 0,
                'avg_completion': 0,
                'last_status': 'pending'
            }
        locker_stats[locker_qr]['inspections'] += 1
        locker_stats[locker_qr]['avg_completion'] += inspection.completion_percentage
        locker_stats[locker_qr]['last_status'] = inspection.status
    
    # Calculate averages
    for qr_code, stats in locker_stats.items():
        if stats['inspections'] > 0:
            stats['avg_completion'] = stats['avg_completion'] / stats['inspections']
    
    return render_template('admin/dashboard.html',
                         total_users=User.query.count(),
                         total_equipment=Equipment.query.count(),
                         total_inspections=total_inspections,
                         passed_inspections=passed_inspections,
                         failed_inspections=failed_inspections,
                         warning_inspections=warning_inspections,
                         recent_inspections=recent_inspections[:10],
                         locker_stats=locker_stats,
                         available_lockers=UNIT_9110_INVENTORY)

@app.route('/admin/generate-qr/<qr_code>')
@login_required 
def generate_qr_code(qr_code):
    """Generate QR code for printing"""
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        if qr_code not in UNIT_9110_INVENTORY:
            flash('Invalid QR code', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr_url = f"{request.url_root}locker/{qr_code}"
        qr.add_data(qr_url)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        locker_data = UNIT_9110_INVENTORY[qr_code]
        
        return render_template('admin/qr_display.html',
                             locker=locker_data,
                             qr_code=qr_code,
                             qr_image=img_str,
                             qr_url=qr_url)
    
    except Exception as e:
        logger.error(f"Error generating QR code: {e}")
        flash('Error generating QR code', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/inspection-report')
@login_required
def inspection_report():
    """Generate inspection report for export"""
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    # Get date range from query params
    days = int(request.args.get('days', 7))
    start_date = datetime.utcnow() - timedelta(days=days)
    
    inspections = Inspection.query.filter(Inspection.inspection_date >= start_date)\
        .order_by(Inspection.inspection_date.desc()).all()
    
    return render_template('admin/inspection_report.html',
                         inspections=inspections,
                         days=days,
                         start_date=start_date)

# Initialize database on startup
try:
    with app.app_context():
        initialize_database()
except Exception as e:
    logger.error(f"Startup initialization failed: {e}")

if __name__ == '__main__':
    app.run(debug=True)