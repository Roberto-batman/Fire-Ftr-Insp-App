# app.py - Fire Truck Inspection System
# Flask 3.0 compatible with proper database initialization

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

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'

# Database configuration
def get_database_uri():
    """Configure database URI based on environment"""
    if os.environ.get('WEBSITE_HOSTNAME'):  # Running on Azure
        # Azure SQL Database with SQL Authentication
        server = os.environ.get('DB_SERVER', 'fire-insp-simple-server.database.windows.net')
        database = os.environ.get('DB_NAME', 'fire-inspection-db-simple')
        username = os.environ.get('DB_USERNAME', 'fireadmin')
        password = os.environ.get('DB_PASSWORD', '')
        
        if not password:
            print("WARNING: No database password found in environment variables")
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
        # Local development with SQLite
        return 'sqlite:///fire_inspection.db'

app.config['SQLALCHEMY_DATABASE_URI'] = get_database_uri()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Database Models
class User(UserMixin, db.Model):
    """User model for authentication"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=True)  # Force password change on first login
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)

class Equipment(db.Model):
    """Equipment model for fire trucks and equipment"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    equipment_type = db.Column(db.String(50), nullable=False)  # 'truck', 'equipment', etc.
    serial_number = db.Column(db.String(100))
    location = db.Column(db.String(100))
    qr_code = db.Column(db.String(100), unique=True)  # QR code identifier
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Inspection(db.Model):
    """Inspection records"""
    id = db.Column(db.Integer, primary_key=True)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    inspection_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, passed, failed
    notes = db.Column(db.Text)
    
    # Relationships
    equipment = db.relationship('Equipment', backref='inspections')
    user = db.relationship('User', backref='inspections')

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    return User.query.get(int(user_id))

def initialize_database():
    """Initialize database with default data"""
    try:
        # Create all tables
        db.create_all()
        
        # Check if admin users already exist
        if User.query.filter_by(username='WBrunton_a').first():
            print("Database already initialized")
            return
        
        print("Initializing database with default users and equipment...")
        
        # Create admin users
        admin1 = User(
            username='WBrunton_a',
            is_admin=True,
            must_change_password=True
        )
        admin1.set_password('TempAdmin123!')  # Temporary password
        
        admin2 = User(
            username='HGirard_a',
            is_admin=True,
            must_change_password=True
        )
        admin2.set_password('TempAdmin123!')  # Temporary password
        
        # Create regular users
        user1 = User(
            username='WBrunton',
            is_admin=False,
            must_change_password=True
        )
        user1.set_password('TempUser123!')  # Temporary password
        
        user2 = User(
            username='HGirard',
            is_admin=False,
            must_change_password=True
        )
        user2.set_password('TempUser123!')  # Temporary password
        
        # Add users to database
        db.session.add_all([admin1, admin2, user1, user2])
        
        # Create sample equipment from the Excel file
        equipment_list = [
            {'name': 'Unit 9110 - Pumper Truck', 'type': 'truck', 'serial': 'ESP-9110', 'location': 'Bay 1', 'qr': 'ESP9110'},
            {'name': 'Unit 9111 - Rescue Truck', 'type': 'truck', 'serial': 'ESP-9111', 'location': 'Bay 2', 'qr': 'ESP9111'},
            {'name': 'Portable Radio Set A', 'type': 'equipment', 'serial': 'RAD-001', 'location': 'Truck 9110', 'qr': 'RAD001'},
            {'name': 'SCBA Unit 1', 'type': 'equipment', 'serial': 'SCBA-001', 'location': 'Truck 9110', 'qr': 'SCBA001'},
            {'name': 'Fire Hose 50ft', 'type': 'equipment', 'serial': 'HOSE-001', 'location': 'Truck 9110', 'qr': 'HOSE001'},
        ]
        
        for eq in equipment_list:
            equipment = Equipment(
                name=eq['name'],
                equipment_type=eq['type'],
                serial_number=eq['serial'],
                location=eq['location'],
                qr_code=eq['qr']
            )
            db.session.add(equipment)
        
        # Commit all changes
        db.session.commit()
        print("✅ Database initialized successfully!")
        print("👤 Admin users created: WBrunton_a, HGirard_a (password: TempAdmin123!)")
        print("👤 Regular users created: WBrunton, HGirard (password: TempUser123!)")
        print("🚛 Sample equipment added from Espanola Fire Department")
        
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        db.session.rollback()

# Routes
@app.route('/')
def index():
    """Main landing page"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Check if user needs to change password
            if user.must_change_password:
                flash('You must change your password before continuing', 'warning')
                return redirect(url_for('change_password'))
            
            flash(f'Welcome, {username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Force password change for new users"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('change_password.html')
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('change_password.html')
        
        # Update password
        current_user.set_password(new_password)
        current_user.must_change_password = False
        db.session.commit()
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    if current_user.must_change_password:
        return redirect(url_for('change_password'))
    
    recent_inspections = Inspection.query.filter_by(user_id=current_user.id).order_by(Inspection.inspection_date.desc()).limit(5).all()
    equipment_count = Equipment.query.filter_by(active=True).count()
    
    return render_template('dashboard.html', 
                         recent_inspections=recent_inspections,
                         equipment_count=equipment_count)

@app.route('/qr_scanner')
@login_required
def qr_scanner():
    """QR code scanner interface"""
    if current_user.must_change_password:
        return redirect(url_for('change_password'))
    return render_template('qr_scanner.html')

@app.route('/equipment/<qr_code>')
@login_required
def equipment_detail(qr_code):
    """Equipment detail page"""
    if current_user.must_change_password:
        return redirect(url_for('change_password'))
    
    equipment = Equipment.query.filter_by(qr_code=qr_code, active=True).first_or_404()
    recent_inspections = Inspection.query.filter_by(equipment_id=equipment.id).order_by(Inspection.inspection_date.desc()).limit(10).all()
    
    return render_template('equipment_detail.html', 
                         equipment=equipment,
                         recent_inspections=recent_inspections)

@app.route('/inspect/<int:equipment_id>', methods=['GET', 'POST'])
@login_required
def inspect_equipment(equipment_id):
    """Inspection form"""
    if current_user.must_change_password:
        return redirect(url_for('change_password'))
    
    equipment = Equipment.query.get_or_404(equipment_id)
    
    if request.method == 'POST':
        status = request.form.get('status')
        notes = request.form.get('notes', '')
        
        inspection = Inspection(
            equipment_id=equipment_id,
            user_id=current_user.id,
            status=status,
            notes=notes
        )
        
        db.session.add(inspection)
        db.session.commit()
        
        flash(f'Inspection completed for {equipment.name}', 'success')
        return redirect(url_for('equipment_detail', qr_code=equipment.qr_code))
    
    return render_template('inspect_equipment.html', equipment=equipment)

@app.route('/admin')
@login_required
def admin_dashboard():
    """Admin dashboard"""
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    if current_user.must_change_password:
        return redirect(url_for('change_password'))
    
    total_users = User.query.count()
    total_equipment = Equipment.query.count()
    total_inspections = Inspection.query.count()
    recent_inspections = Inspection.query.order_by(Inspection.inspection_date.desc()).limit(10).all()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_equipment=total_equipment,
                         total_inspections=total_inspections,
                         recent_inspections=recent_inspections)

@app.route('/generate_qr/<int:equipment_id>')
@login_required
def generate_qr(equipment_id):
    """Generate QR code for equipment"""
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    equipment = Equipment.query.get_or_404(equipment_id)
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr_data = f"{request.url_root}equipment/{equipment.qr_code}"
    qr.add_data(qr_data)
    qr.make(fit=True)
    
    # Create QR code image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 for display
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template('qr_display.html', 
                         equipment=equipment,
                         qr_image=img_str,
                         qr_url=qr_data)

# Initialize database when app starts
with app.app_context():
    initialize_database()

if __name__ == '__main__':
    app.run(debug=True)