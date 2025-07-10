import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify, g
from flask_login import current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, time, timedelta, date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from apscheduler.schedulers.background import BackgroundScheduler
from flask_wtf.csrf import CSRFProtect
from openpyxl import Workbook
from io import BytesIO
import atexit
from functools import wraps
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, IntegerField, SelectField, DateField, TimeField
from wtforms.validators import DataRequired, Optional, Email, Length, EqualTo, ValidationError
from wtforms.fields import BooleanField

from sqlalchemy import or_

from forms import ChangePasswordForm

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__, template_folder='templates')

# Configure app
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Email configuration
# In your app.py, ensure this configuration:
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'rabarfbi@gmail.com'  # Your Gmail
app.config['MAIL_PASSWORD'] = 'xqlc dbsy ggde jeyl'  # The 16-char app password
app.config['MAIL_DEFAULT_SENDER'] = 'School Booking System <rabarfbi@gmail.com>'

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)
csrf = CSRFProtect(app)

# Initialize scheduler with app context
def init_scheduler(app):
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())
    return scheduler

# Then initialize it after creating your app
scheduler = init_scheduler(app)


def create_scheduler(app):
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())

    # Store the app reference in the scheduler
    scheduler.app = app
    return scheduler


# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    department = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    bookings = db.relationship('Booking', backref='user', lazy=True)


class Facility(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    max_capacity = db.Column(db.Integer, nullable=True)
    booking_rules = db.Column(db.Text, nullable=True)


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    facility_id = db.Column(db.Integer, db.ForeignKey('facility.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    purpose = db.Column(db.String(200))
    status = db.Column(db.String(20), default='approved')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    facility = db.relationship('Facility', backref='bookings')

    @property
    def is_upcoming(self):
        now = datetime.now()
        booking_datetime = datetime.combine(self.date, self.start_time)
        return booking_datetime > now

    @property
    def is_completed(self):
        now = datetime.now()
        booking_datetime = datetime.combine(self.date, self.end_time)
        return booking_datetime < now


# Blackout periods for facilities
FACILITY_BLACKOUTS = {
    'Canteen': [
        {'start': time(10, 0), 'end': time(10, 30)},
        {'start': time(12, 0), 'end': time(13, 0)},
        {'start': time(14, 30), 'end': time(14, 45)}
    ]
}


# Form Classes
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class AdminRegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8),
        EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField('Confirm Password')
    department = SelectField('Department', choices=[
        ('primary', 'Primary School'),
        ('secondary', 'Secondary School'),
        ('administration', 'Administration'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    is_admin = BooleanField('Admin Privileges')
    is_active = BooleanField('Active Account', default=True)


class ProfileForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    current_password = PasswordField('Current Password', validators=[Optional()])
    new_password = PasswordField('New Password', validators=[
        Optional(),
        Length(min=8),
        EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[Optional()])


class BookingForm(FlaskForm):
    facility_id = SelectField('Facility', coerce=int, validators=[DataRequired()])
    date = DateField('Date', format='%Y-%m-%d', validators=[DataRequired()])
    start_time = TimeField('Start Time', format='%H:%M', validators=[DataRequired()])
    end_time = TimeField('End Time', format='%H:%M', validators=[DataRequired()])
    purpose = TextAreaField('Purpose', validators=[DataRequired(), Length(max=200)])

    def validate_end_time(self, field):
        if self.start_time.data and field.data and field.data <= self.start_time.data:
            raise ValidationError('End time must be after start time')

    def validate_date(self, field):
        if field.data and field.data < datetime.now().date():
            raise ValidationError('Booking date must be today or in the future')


class FacilityForm(FlaskForm):
    name = StringField('Facility Name', validators=[DataRequired(), Length(max=50)])
    description = TextAreaField('Description', validators=[Optional(), Length(max=200)])
    max_capacity = IntegerField('Maximum Capacity', validators=[Optional()])
    booking_rules = TextAreaField('Booking Rules', validators=[Optional()])


class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    department = SelectField('Department', choices=[
        ('primary', 'Primary School'),
        ('secondary', 'Secondary School'),
        ('administration', 'Administration'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    is_admin = BooleanField('Is Admin')
    is_active = BooleanField('Is Active')


# Helper functions
def is_blackout_time(facility_name, selected_time):
    blackouts = FACILITY_BLACKOUTS.get(facility_name, [])
    for blackout in blackouts:
        if blackout['start'] <= selected_time.time() <= blackout['end']:
            return True
    return False


def send_reminder_email(booking_id, reminder_type='confirmation'):
    try:
        booking = db.session.get(Booking, booking_id)
        if not booking:
            app.logger.error(f"Booking {booking_id} not found for reminder")
            return False

        user = booking.user
        facility = booking.facility

        templates = {
            'confirmation': ('emails/confirmation.txt',
                             f"Booking Confirmation: {facility.name}"),
            'week_before': ('emails/week_reminder.txt',
                            f"Reminder: Upcoming booking at {facility.name}"),
            'day_before': ('emails/day_reminder.txt',
                           f"Reminder: Your booking is tomorrow"),
            '30_min_before': ('emails/30min_reminder.txt',
                              f"Reminder: Booking starts soon")
        }

        template_file, subject = templates.get(reminder_type,
                                               ('emails/confirmation.txt',
                                                f"Booking Notification: {facility.name}"))

        body = render_template(template_file, booking=booking, user=user)

        msg = Message(
            subject=subject,
            recipients=[user.email],
            body=body,
            sender=app.config['MAIL_DEFAULT_SENDER']  # Explicitly set sender
        )

        mail.send(msg)
        app.logger.info(f"Sent {reminder_type} email for booking {booking_id}")
        return True

    except Exception as e:
        app.logger.error(f"Failed to send email for booking {booking_id}: {str(e)}")
        return False

    def send_cancellation_email(booking):
        try:
            msg = Message(
                subject=f"Booking Cancelled: {booking.facility.name}",
                recipients=[booking.user.email],
                body=f"Your booking has been cancelled:\n\n"
                     f"Facility: {booking.facility.name}\n"
                     f"Date: {booking.date.strftime('%Y-%m-%d')}\n"
                     f"Time: {booking.start_time.strftime('%H:%M')} - {booking.end_time.strftime('%H:%M')}",
                sender=app.config['MAIL_DEFAULT_SENDER']
            )
            mail.send(msg)
        except Exception as e:
            app.logger.error(f"Failed to send cancellation email: {str(e)}")


def schedule_booking_reminders(booking):
    booking_datetime = datetime.combine(booking.date, booking.start_time)

    # 1 week before
    week_before = booking_datetime - timedelta(days=7)
    if week_before > datetime.now():
        scheduler.add_job(
            lambda: send_reminder_email(booking.id, 'week_before'),
            'date',
            run_date=week_before,
            id=f'week_{booking.id}'
        )

    # 1 day before
    day_before = booking_datetime - timedelta(days=1)
    if day_before > datetime.now():
        scheduler.add_job(
            lambda: send_reminder_email(booking.id, 'day_before'),
            'date',
            run_date=day_before,
            id=f'day_{booking.id}'
        )

    # 30 minutes before
    thirty_min_before = booking_datetime - timedelta(minutes=30)
    if thirty_min_before > datetime.now():
        scheduler.add_job(
            lambda: send_reminder_email(booking.id, '30_min_before'),
            'date',
            run_date=thirty_min_before,
            id=f'30min_{booking.id}'
        )

def remove_scheduled_reminders(booking_id):
    for reminder_type in ['week', 'day', '30min']:
        try:
            scheduler.remove_job(f'{reminder_type}_{booking_id}')
        except:
            pass


def has_booking_conflict(facility_id, date, start_time, end_time, exclude_id=None):
    query = db.session.query(Booking).filter(
        Booking.facility_id == facility_id,
        Booking.date == date,
        Booking.status.in_(['approved', 'pending'])
    )

    if exclude_id:
        query = query.filter(Booking.id != exclude_id)

    bookings = query.all()

    new_start = datetime.combine(date, start_time)
    new_end = datetime.combine(date, end_time)

    for booking in bookings:
        existing_start = datetime.combine(booking.date, booking.start_time)
        existing_end = datetime.combine(booking.date, booking.end_time)

        if (new_start < existing_end) and (new_end > existing_start):
            return True

    return False


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# Initialize application data
def initialize_data():
    with app.app_context():
        db.create_all()

        # Create default facilities
        if not db.session.query(Facility).first():
            facilities = [
                Facility(name='Playground', description='Outdoor play area', max_capacity=50),
                Facility(name='Canteen', description='Dining area', max_capacity=100),
                Facility(name='Auditorium', description='Multi-purpose hall', max_capacity=200),
                Facility(name='Library', description='Reading and study area', max_capacity=30),
                Facility(name='Computer Lab', description='Technology center', max_capacity=25)
            ]
            db.session.bulk_save_objects(facilities)
            db.session.commit()

        # Create admin user
        if not db.session.query(User).filter_by(is_admin=True).first():
            admin = User(
                username='admin',
                email=os.getenv('ADMIN_EMAIL', 'admin@example.com'),
                password=generate_password_hash(os.getenv('ADMIN_PASSWORD', 'admin123')),
                is_admin=True,
                department='Administration',
                is_active=True
            )
            db.session.add(admin)
            db.session.commit()


@app.context_processor
def inject_datetime():
    return {'datetime': datetime, 'current_user': g.user}


@app.before_request
def load_user():
    g.user = None
    if 'user_id' in session:
        g.user = db.session.get(User, session['user_id'])


@app.before_request
def check_active_user():
    if request.endpoint in ['login', 'static', 'home']:
        return
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user and not user.is_active:
            session.clear()
            flash('Your account has been deactivated', 'danger')
            return redirect(url_for('login'))


# Routes
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter_by(username=form.username.data).first()

        if not user:
            flash('Invalid username or password', 'danger')
        elif not user.is_active:
            flash('Your account is deactivated', 'danger')
        elif check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            session['department'] = user.department
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = db.session.get(User, session['user_id'])
    user_bookings = db.session.query(Booking).filter_by(user_id=user.id).order_by(Booking.date.desc()).limit(5).all()

    stats = {
        'total_bookings': db.session.query(Booking).count(),
        'active_users': db.session.query(User).filter_by(is_active=True).count(),
        'upcoming_bookings': db.session.query(Booking).filter(Booking.date >= datetime.now().date()).count(),
        'facilities': db.session.query(Facility).count()
    }

    return render_template('dashboard.html',
                           user=user,
                           user_bookings=user_bookings,
                           stats=stats)


def notify_admin_of_booking(booking):
    pass


@app.route('/book', methods=['GET', 'POST'])
@login_required
def book():
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('login'))

        facilities = db.session.query(Facility).order_by(Facility.name).all()
        if not facilities:
            flash('No facilities available for booking', 'warning')
            return redirect(url_for('dashboard'))

        form = BookingForm()
        form.facility_id.choices = [(f.id, f"{f.name} - {f.description}") for f in facilities]

        if form.validate_on_submit():
            facility = db.session.get(Facility, form.facility_id.data)
            if not facility:
                flash('Invalid facility selected', 'danger')
                return redirect(url_for('book'))

            # Validate time
            if form.end_time.data <= form.start_time.data:
                flash('End time must be after start time', 'danger')
                return redirect(url_for('book'))

            # Check blackout periods
            if is_blackout_time(facility.name, datetime.combine(form.date.data, form.start_time.data)):
                flash(f'{facility.name} cannot be booked during restricted times', 'danger')
                return redirect(url_for('book'))

            # Check for conflicts
            if has_booking_conflict(form.facility_id.data, form.date.data,
                                    form.start_time.data, form.end_time.data):
                flash('This time slot is already booked', 'danger')
                return redirect(url_for('book'))

            # Create booking
            booking = Booking(
                user_id=user.id,
                facility_id=form.facility_id.data,
                date=form.date.data,
                start_time=form.start_time.data,
                end_time=form.end_time.data,
                purpose=form.purpose.data,
                status='approved' if user.is_admin else 'pending'
            )

            db.session.add(booking)
            db.session.commit()

            # Send notifications
            send_reminder_email(booking.id)
            schedule_booking_reminders(booking)

            if not user.is_admin:
                notify_admin_of_booking(booking)

            flash('Booking created successfully!', 'success')
            return redirect(url_for('view_bookings'))

        min_date = datetime.now().strftime('%Y-%m-%d')
        max_date = (datetime.now() + timedelta(days=60)).strftime('%Y-%m-%d')

        return render_template('booking.html',
                               form=form,
                               facilities=facilities,
                               min_date=min_date,
                               max_date=max_date)

    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {str(e)}', 'danger')
        app.logger.error(f"Booking error: {str(e)}")
        return redirect(url_for('dashboard'))


@app.route('/booking/<int:booking_id>', methods=['GET', 'POST'])
@login_required
def view_booking(booking_id):
    booking = db.session.get(Booking, booking_id)
    if not booking:
        flash('Booking not found', 'danger')
        return redirect(url_for('dashboard'))

    user = db.session.get(User, session['user_id'])

    # Authorization check
    if not user.is_admin and booking.user_id != user.id:
        flash('You can only view your own bookings', 'danger')
        return redirect(url_for('dashboard'))

    return render_template('view_booking.html', booking=booking)


@app.route('/bookings/<int:booking_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_booking(booking_id):
    booking = db.session.query(Booking).options(db.joinedload(Booking.facility)) \
        .filter_by(id=booking_id) \
        .first()

    if not booking:
        flash('Booking not found', 'danger')
        return redirect(url_for('dashboard'))

    # For non-admin users, only allow viewing their own bookings
    if not session.get('is_admin') and booking.user_id != session['user_id']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))

    facilities = db.session.query(Facility).order_by(Facility.name).all()
    today = date.today()
    max_date = today + timedelta(days=90)

    return render_template('edit_booking.html',
                           booking=booking,
                           facilities=facilities,
                           min_date=today.strftime('%Y-%m-%d'),
                           max_date=max_date.strftime('%Y-%m-%d'))


@app.route('/booking/<int:booking_id>/cancel', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    form = FlaskForm()
    if form.validate_on_submit():
        booking = db.session.get(Booking, booking_id)
        if not booking:
            flash('Booking not found', 'danger')
            return redirect(url_for('dashboard'))

        user = db.session.get(User, session['user_id'])

        # Authorization check
        if not user.is_admin and booking.user_id != user.id:
            flash('You can only cancel your own bookings', 'danger')
            return redirect(url_for('dashboard'))

        booking.status = 'cancelled'
        db.session.commit()

        # Remove scheduled reminders
        remove_scheduled_reminders(booking.id)

        # Send cancellation email
        send_cancellation_email(booking)

        flash('Booking cancelled successfully', 'success')
    return redirect(url_for('dashboard'))


def send_cancellation_email(booking):
    try:
        msg = Message(
            subject=f"Booking Cancelled: {booking.facility.name}",
            recipients=[booking.user.email],
            body=f"Your booking has been cancelled:\n\n"
                 f"Facility: {booking.facility.name}\n"
                 f"Date: {booking.date.strftime('%Y-%m-%d')}\n"
                 f"Time: {booking.start_time.strftime('%H:%M')} - {booking.end_time.strftime('%H:%M')}"
        )
        mail.send(msg)
    except Exception as e:
        app.logger.error(f"Failed to send cancellation email: {str(e)}")


@app.route('/bookings')
@login_required
def view_bookings():
    facility_id = request.args.get('facility_id', type=int)
    date_str = request.args.get('date')
    status = request.args.get('status', 'all')

    # Base query
    query = db.session.query(Booking)

    # Apply filters
    if facility_id:
        query = query.filter_by(facility_id=facility_id)

    if date_str:
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
            query = query.filter_by(date=date)
        except ValueError:
            pass

    if status != 'all':
        query = query.filter_by(status=status)

    bookings = query.order_by(Booking.date.desc(), Booking.start_time.desc()).all()
    facilities = db.session.query(Facility).all()

    return render_template('view_bookings.html',
                           bookings=bookings,
                           facilities=facilities,
                           selected_facility=facility_id,
                           selected_date=date_str,
                           selected_status=status)


@app.route('/calendar')
@login_required
def calendar_view():
    return render_template('calendar.html')


@app.route('/api/bookings')
def get_bookings():
    bookings = db.session.query(Booking).all()

    events = []
    for booking in bookings:
        events.append({
            'id': booking.id,
            'title': f"{booking.facility.name} - {booking.user.username}",
            'start': f"{booking.date}T{booking.start_time.strftime('%H:%M:%S')}",
            'end': f"{booking.date}T{booking.end_time.strftime('%H:%M:%S')}",
            'color': '#3498db' if booking.user.department == 'primary' else '#e74c3c',
            'extendedProps': {
                'facility': booking.facility.name,
                'username': booking.user.username,
                'department': booking.user.department,
                'purpose': booking.purpose,
                'status': booking.status
            }
        })

    return jsonify(events)


@app.route('/export/bookings')
@login_required
@admin_required
def export_bookings():
    bookings = db.session.query(Booking).options(
        db.joinedload(Booking.facility),
        db.joinedload(Booking.user)
    ).all()

    wb = Workbook()
    ws = wb.active
    ws.title = "Bookings"

    # Headers
    headers = ["ID", "Facility", "Date", "Start Time", "End Time", "User", "Department", "Purpose", "Status"]
    ws.append(headers)

    # Data
    for booking in bookings:
        ws.append([
            booking.id,
            booking.facility.name,
            booking.date.strftime('%Y-%m-%d'),
            booking.start_time.strftime('%H:%M'),
            booking.end_time.strftime('%H:%M'),
            booking.user.username,
            booking.user.department,
            booking.purpose,
            booking.status
        ])

    # Save to buffer
    buffer = BytesIO()
    wb.save(buffer)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"bookings_export_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = db.session.query(User).all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/user/<int:user_id>')
@login_required
@admin_required
def view_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_users'))

    user_bookings = db.session.query(Booking).filter_by(user_id=user_id).order_by(Booking.date.desc()).limit(5).all()
    return render_template('view_user.html', user=user, bookings=user_bookings)

@app.route('/admin/users/<int:user_id>')
@login_required
@admin_required
def user_details(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_users'))
    return render_template('admin_users.html', user=user)


@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_users'))

    form = UserForm(obj=user)

    if form.validate_on_submit():
        # Check if username is already taken
        if db.session.query(User).filter(User.username == form.username.data, User.id != user.id).first():
            flash('Username already taken', 'danger')
            return redirect(url_for('edit_user', user_id=user.id))

        # Check if email is already in use
        if db.session.query(User).filter(User.email == form.email.data, User.id != user.id).first():
            flash('Email already in use', 'danger')
            return redirect(url_for('edit_user', user_id=user.id))

        form.populate_obj(user)
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('view_user', user_id=user.id))

    return render_template('edit_user.html', user=user, form=form)


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    form = FlaskForm()
    if form.validate_on_submit():
        user = db.session.get(User, user_id)
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_users'))

        # Prevent deleting own account
        if user.id == session['user_id']:
            flash('You cannot delete your own account', 'danger')
            return redirect(url_for('admin_users'))

        # Delete user's bookings first
        db.session.query(Booking).filter_by(user_id=user_id).delete()

        db.session.delete(user)
        db.session.commit()

        flash('User deleted successfully', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_user(user_id):
    form = FlaskForm()
    if form.validate_on_submit():
        user = db.session.get(User, user_id)
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_users'))

        user.is_active = not user.is_active
        db.session.commit()

        status = "activated" if user.is_active else "deactivated"
        flash(f"User {user.username} has been {status}", "success")

        # Log out the user if deactivated
        if not user.is_active and session.get('user_id') == user.id:
            session.clear()
            return redirect(url_for('login'))

    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/reset-password', methods=['GET', 'POST'])
@login_required
@admin_required
def reset_user_password(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_users'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('Both fields are required', 'danger')
        elif new_password != confirm_password:
            flash('Passwords do not match', 'danger')
        else:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash("Password reset successfully", "success")
            return redirect(url_for('view_user', user_id=user.id))  # Make sure this matches

    return render_template('admin_reset_password.html', user=user)

@app.route('/admin/register', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_register_user():
    form = AdminRegisterForm()
    if form.validate_on_submit():
        # Check if username already exists
        if db.session.query(User).filter_by(username=form.username.data).first():
            flash('Username already taken', 'danger')
            return redirect(url_for('admin_register_user'))

        # Check if email already exists
        if db.session.query(User).filter_by(email=form.email.data).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('admin_register_user'))

        try:
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=generate_password_hash(form.password.data),
                department=form.department.data,
                is_admin=form.is_admin.data,
                is_active=form.is_active.data
            )
            db.session.add(new_user)
            db.session.commit()
            flash('User registered successfully!', 'success')
            return redirect(url_for('admin_users'))

        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'danger')
            app.logger.error(f"Registration error: {str(e)}")

    return render_template('admin_register.html', form=form)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def view_profile():
    user = db.session.get(User, session['user_id'])
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('login'))

    form = ProfileForm(obj=user)

    if form.validate_on_submit():
        if form.email.data != user.email:
            if db.session.query(User).filter(User.email == form.email.data, User.id != user.id).first():
                flash('Email already in use', 'danger')
            else:
                user.email = form.email.data
                flash('Email updated successfully', 'success')

        if form.current_password.data and form.new_password.data:
            if check_password_hash(user.password, form.current_password.data):
                user.password = generate_password_hash(form.new_password.data)
                flash('Password updated successfully', 'success')
            else:
                flash('Current password is incorrect', 'danger')

        db.session.commit()
        return redirect(url_for('view_profile'))

    bookings = db.session.query(Booking).filter_by(user_id=user.id).order_by(Booking.date.desc()).limit(5).all()

    return render_template('profile.html', form=form, user=user, bookings=bookings)


@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = db.session.get(User, session['user_id'])
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('login'))

    form = ProfileForm(obj=user)

    if form.validate_on_submit():
        # Check if email is changed and already in use
        if form.email.data != user.email:
            existing_user = db.session.query(User).filter(User.email == form.email.data, User.id != user.id).first()
            if existing_user:
                flash('Email already in use by another account.', 'danger')
                return redirect(url_for('edit_profile'))
            else:
                user.email = form.email.data
                flash('Email updated successfully.', 'success')

        # Handle password change
        if form.current_password.data and form.new_password.data:
            if check_password_hash(user.password, form.current_password.data):
                user.password = generate_password_hash(form.new_password.data)
                flash('Password updated successfully.', 'success')
            else:
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('edit_profile'))

        db.session.commit()
        return redirect(url_for('view_profile'))

    return render_template('edit_profile.html', form=form, user=user)


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    user = db.session.get(User, session['user_id'])
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('login'))

    if form.validate_on_submit():
        # Verify current password
        if not check_password_hash(user.password, form.current_password.data):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('change_password'))

        # Update password
        user.password = generate_password_hash(form.new_password.data)
        db.session.commit()

        flash('Your password has been updated successfully!', 'success')
        return redirect(url_for('view_profile'))

    return render_template('change_password.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
@login_required
@admin_required
def register():
    form = AdminRegisterForm()

    if form.validate_on_submit():
        if db.session.query(User).filter_by(username=form.username.data).first():
            flash('Username already taken', 'danger')
            return redirect(url_for('register'))

        if db.session.query(User).filter_by(email=form.email.data).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        try:
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=generate_password_hash(form.password.data),
                department=form.department.data,
                is_admin=form.is_admin.data,
                is_active=form.is_active.data
            )
            db.session.add(new_user)
            db.session.commit()
            flash('User registered successfully!', 'success')
            return redirect(url_for('admin_users'))

        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'danger')
            app.logger.error(f"Registration error: {str(e)}")

    return render_template('register.html', form=form)


@app.route('/admin/facilities')
@login_required
@admin_required
def manage_facilities():
    facilities = db.session.query(Facility).all()
    return render_template('admin_facilities.html', facilities=facilities)


@app.route('/admin/facility/<int:facility_id>')
@login_required
@admin_required
def view_facility(facility_id):
    facility = db.session.get(Facility, facility_id)
    if not facility:
        flash('Facility not found', 'danger')
        return redirect(url_for('manage_facilities'))
    return render_template('view_facility.html', facility=facility)


@app.route('/admin/facility/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_facility():
    form = FacilityForm()
    if form.validate_on_submit():
        facility = Facility(
            name=form.name.data,
            description=form.description.data,
            max_capacity=form.max_capacity.data,
            booking_rules=form.booking_rules.data
        )
        db.session.add(facility)
        db.session.commit()
        flash('Facility added successfully', 'success')
        return redirect(url_for('manage_facilities'))
    return render_template('edit_facility.html', form=form, facility=None)


@app.route('/admin/facility/<int:facility_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_facility(facility_id):
    facility = db.session.get(Facility, facility_id)
    if not facility:
        flash('Facility not found', 'danger')
        return redirect(url_for('manage_facilities'))

    form = FacilityForm(obj=facility)

    if form.validate_on_submit():
        form.populate_obj(facility)
        db.session.commit()
        flash('Facility updated successfully', 'success')
        return redirect(url_for('view_facility', facility_id=facility.id))

    return render_template('edit_facility.html', facility=facility, form=form)


@app.route('/facility/<int:facility_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_facility(facility_id):
    form = FlaskForm()
    if form.validate_on_submit():
        facility = db.session.get(Facility, facility_id)
        if not facility:
            flash('Facility not found', 'danger')
            return redirect(url_for('manage_facilities'))

        # Check for existing bookings
        if db.session.query(Booking).filter_by(facility_id=facility_id).count() > 0:
            flash('Cannot delete facility with existing bookings', 'danger')
            return redirect(url_for('manage_facilities'))

        db.session.delete(facility)
        db.session.commit()
        flash('Facility deleted successfully', 'success')
    else:
        flash('Invalid request', 'danger')
    return redirect(url_for('manage_facilities'))


if __name__ == '__main__':
    initialize_data()
    app.run(debug=True)