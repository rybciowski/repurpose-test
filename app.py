import os
import datetime
import secrets
import subprocess
import uuid # Do generowania unikalnych nazw plików
from functools import wraps
import pathlib # Do konwersji ścieżek dla FFmpeg
import traceback

import click
import requests
from PIL import Image
from user_agents import parse
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect, CSRFError # Import CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room

# Import funkcji przetwarzającej wideo
try:
    from video_processor import process_video_ffmpeg
except ImportError:
    print("OSTRZEŻENIE: Nie można zaimportować 'process_video_ffmpeg' z video_processor.py. Funkcjonalność generacji wideo będzie ograniczona.")
    def process_video_ffmpeg(input_path, output_path, settings_dict):
        print(f"WYWOŁANO ATRAPĘ process_video_ffmpeg: {input_path} -> {output_path} z ustawieniami {settings_dict}")
        import shutil
        try:
            if not os.path.exists(os.path.dirname(output_path)):
                os.makedirs(os.path.dirname(output_path))
            shutil.copy(input_path, output_path)
            return True, output_path
        except Exception as e:
            return False, str(e)


# --- KONFIGURACJA APLIKACJI ---
app = Flask(__name__)
# Odczytuje SECRET_KEY ze zmiennej środowiskowej; jeśli nie ma, używa wartości domyślnej.
# PAMIĘTAJ, aby ustawić silny SECRET_KEY w zmiennych środowiskowych na Render.com!
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'domyslny_bardzo_slaby_klucz_do_zmiany_123!@#')

basedir = os.path.abspath(os.path.dirname(__file__))

# Konfiguracja URI bazy danych: używa DATABASE_URL ze zmiennej środowiskowej (ustawisz to na Render),
# a jeśli jej nie ma (np. lokalnie), używa lokalnego pliku SQLite.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///' + os.path.join(basedir, 'database.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Konfiguracja folderów dla awatarów użytkowników
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/avatars')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}

# Konfiguracje dla przesyłania i generowania wideo
# Pamiętaj, że w darmowym planie Render system plików jest efemeryczny - te pliki będą tymczasowe.
app.config['UPLOAD_VIDEO_FOLDER'] = os.path.join(basedir, 'uploads')
app.config['GENERATED_VIDEO_FOLDER'] = os.path.join(basedir, 'generated')
app.config['ALLOWED_VIDEO_EXTENSIONS'] = {'mp4'}
app.config['MAX_VIDEO_FILE_SIZE'] = 100 * 1024 * 1024  # 100 MB

# Upewnij się, że katalogi dla plików istnieją.
# Ważne dla platform z efemerycznym systemem plików (jak Render w darmowym planie).
try:
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['UPLOAD_VIDEO_FOLDER'], exist_ok=True)
    os.makedirs(app.config['GENERATED_VIDEO_FOLDER'], exist_ok=True)
    # Dodatkowe logi (print) dla potwierdzenia, że foldery są tworzone lub istnieją
    print(f"Folder dla awatarów: {app.config['UPLOAD_FOLDER']} - status OK")
    print(f"Folder dla przesyłanych wideo: {app.config['UPLOAD_VIDEO_FOLDER']} - status OK")
    print(f"Folder dla wygenerowanych wideo: {app.config['GENERATED_VIDEO_FOLDER']} - status OK")
except OSError as e:
    # W przypadku błędu (np. brak uprawnień), aplikacja będzie nadal próbowała działać,
    # ale operacje na plikach mogą się nie udać. Logowanie błędu jest ważne.
    print(f"OSTRZEŻENIE: Nie udało się utworzyć folderów konfiguracyjnych: {e}")
# --- Koniec sekcji KONFIGURACJA APLIKACJI ---

# --- INICJALIZACJA ROZSZERZEŃ ---
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"], storage_uri="memory://")
socketio = SocketIO(app)


# --- MODELE BAZY DANYCH ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    access_expires_at = db.Column(db.DateTime, nullable=True)
    is_blocked = db.Column(db.Boolean, default=False, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    avatar = db.Column(db.String(100), nullable=False, default='default.jpg')
    bio = db.Column(db.Text, nullable=True)

class SystemSetting(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(100), nullable=False)

class AccessKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    validity_days = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='aktywny', nullable=False) 
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    used_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    used_at = db.Column(db.DateTime, nullable=True)
    used_by = db.relationship('User', backref=db.backref('used_key', uselist=False))

class BaseSessionInfo(db.Model):
    __abstract__ = True
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent_raw = db.Column(db.String(255), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    country = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    isp = db.Column(db.String(100), nullable=True)
    browser = db.Column(db.String(50), nullable=True)
    os = db.Column(db.String(50), nullable=True)
    device_type = db.Column(db.String(50), nullable=True)

class ActiveSession(BaseSessionInfo):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.String(255), unique=True, nullable=False)
    user = db.relationship('User', backref=db.backref('active_sessions', lazy=True, cascade="all, delete-orphan"))

class LoginHistory(BaseSessionInfo):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('login_history', lazy=True, cascade="all, delete-orphan", order_by="desc(LoginHistory.login_time)"))

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    event_type = db.Column(db.String(50), nullable=False)
    actor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    target_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    details = db.Column(db.Text, nullable=True)
    actor = db.relationship('User', foreign_keys=[actor_id])
    target = db.relationship('User', foreign_keys=[target_id])

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), default='Oczekujące', nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    user = db.relationship('User', backref='tickets')
    messages = db.relationship('TicketMessage', backref='ticket', lazy='dynamic', cascade="all, delete-orphan")

class TicketMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user = db.relationship('User', backref='ticket_messages')


# --- FUNKCJE POMOCNICZE I DEKORATORY ---
@app.template_filter('nl2br')
def nl2br_filter(s):
    if s is None:
        return ''
    return str(s).replace('\n', '<br>\n')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def allowed_video_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_VIDEO_EXTENSIONS']

def save_avatar(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.config['UPLOAD_FOLDER'], picture_fn)
    output_size = (150, 150)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

def get_setting(key, default=None):
    setting = SystemSetting.query.get(key)
    return setting.value if setting else default

@app.before_request
def before_request_tasks():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])
        if g.user and 'username' not in session:
            session['username'] = g.user.username
        elif not g.user and 'user_id' in session:
            session.clear()

# Obsługa błędów CSRF globalnie
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash(f'Błąd CSRF: {e.description}. Spróbuj ponownie.', 'danger')
    # Możesz przekierować na poprzednią stronę lub stronę główną
    # Użycie request.referrer wymaga ostrożności ze względów bezpieczeństwa (open redirect)
    # Lepiej przekierować na znaną, bezpieczną stronę.
    referrer = request.referrer
    if referrer and url_for('login') not in referrer and url_for('register') not in referrer : # Prosty przykład, aby unikać pętli
        return redirect(referrer)
    return redirect(url_for('index'))


def log_event(event_type, details, actor_id=None, target_id=None):
    if actor_id is None and 'user_id' in session:
        actor_id = session.get('original_user_id', session.get('user_id'))
    log_entry = AuditLog(event_type=event_type, details=details, actor_id=actor_id, target_id=target_id)
    db.session.add(log_entry)
    db.session.commit()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Musisz się zalogować, aby uzyskać dostęp do tej strony.', 'warning')
            return redirect(url_for('login', next=request.url))
        
        user_from_session = User.query.get(session['user_id'])
        if not user_from_session:
            session.clear()
            flash('Wystąpił błąd sesji. Zaloguj się ponownie.', 'danger')
            return redirect(url_for('login'))

        if session.get('is_impersonating') and user_from_session.is_blocked:
            flash(f'Konto użytkownika {user_from_session.username}, w którego się wcielasz, jest zablokowane. Kończenie wcielania.', 'danger')
            original_admin_id = session.get('original_user_id')
            if original_admin_id:
                admin_user = User.query.get(original_admin_id)
                if admin_user:
                    session['user_id'] = admin_user.id
                    session['username'] = admin_user.username
                    session['is_admin'] = admin_user.is_admin
                    session.pop('is_impersonating', None)
                    session.pop('original_user_id', None)
                    session.pop('original_user_username', None)
                    return redirect(url_for('admin_dashboard'))
            session.clear()
            return redirect(url_for('login'))

        is_true_admin_not_impersonating = g.user and g.user.is_admin and not session.get('is_impersonating')
        if not is_true_admin_not_impersonating:
            if g.user.is_blocked:
                flash('Twoje konto jest zablokowane. Skontaktuj się z administratorem.', 'danger')
                session.clear()
                return redirect(url_for('login'))
            if g.user.access_expires_at and g.user.access_expires_at < datetime.datetime.utcnow():
                flash('Twój dostęp do aplikacji wygasł. Skontaktuj się z administratorem.', 'danger')
                session.clear()
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        is_effectively_admin = False
        if session.get('is_impersonating'):
            original_admin_id = session.get('original_user_id')
            if original_admin_id:
                admin_user = User.query.get(original_admin_id)
                if admin_user and admin_user.is_admin:
                    is_effectively_admin = True
        elif g.user and g.user.is_admin:
            is_effectively_admin = True
        
        if not is_effectively_admin:
            flash('Brak uprawnień administratora.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


# --- TRASY APLIKACJI (PUBLICZNE I UWIERZYTELNIANIE) ---
@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.is_admin and not session.get('is_impersonating'):
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", key_func=lambda: request.form.get("username") or request.remote_addr)
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if not user:
            flash('Nieprawidłowa nazwa użytkownika lub hasło.', 'danger')
            return redirect(url_for('login'))

        if user.is_blocked:
            flash('To konto zostało trwale zablokowane przez administratora.', 'danger')
            log_event('LOGIN_FAILED_BLOCKED', f"Próba logowania na zablokowane konto '{username}'.", target_id=user.id)
            return redirect(url_for('login'))

        LOCKOUT_ATTEMPTS = int(get_setting('LOCKOUT_ATTEMPTS', 5))
        LOCKOUT_TIME_MINUTES = int(get_setting('LOCKOUT_TIME_MINUTES', 5))

        if user.failed_login_attempts >= LOCKOUT_ATTEMPTS:
            if user.last_failed_login and datetime.datetime.utcnow() < user.last_failed_login + datetime.timedelta(minutes=LOCKOUT_TIME_MINUTES):
                time_left = (user.last_failed_login + datetime.timedelta(minutes=LOCKOUT_TIME_MINUTES)) - datetime.datetime.utcnow()
                minutes_left = time_left.seconds // 60 + 1
                flash(f'Konto zablokowane z powodu zbyt wielu prób. Spróbuj ponownie za {minutes_left} minut.', 'warning')
                return redirect(url_for('login'))
            else:
                user.failed_login_attempts = 0
        
        if check_password_hash(user.password_hash, password):
            user.failed_login_attempts = 0
            db.session.commit()
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            session.permanent = True
            session_token = secrets.token_hex(24)
            session['session_token'] = session_token
            ip_addr = request.remote_addr
            user_agent_str = request.headers.get('User-Agent', 'Unknown')
            is_new_device = not ActiveSession.query.filter_by(user_id=user.id, user_agent_raw=user_agent_str).first()
            if is_new_device:
                log_event(event_type='NEW_DEVICE_LOGIN', details=f"Wykryto logowanie z nowego urządzenia/UA dla '{user.username}'. UA: {user_agent_str}", actor_id=user.id)

            enriched_data = {"ip_address": ip_addr, "user_agent_raw": user_agent_str}
            if ip_addr and ip_addr != "127.0.0.1":
                try:
                    response = requests.get(f'https://ip-api.com/json/{ip_addr}?fields=status,message,country,city,isp', timeout=2)
                    response.raise_for_status()
                    ip_data = response.json()
                    if ip_data.get('status') == 'success':
                        enriched_data.update({'country': ip_data.get('country'), 'city': ip_data.get('city'), 'isp': ip_data.get('isp')})
                except requests.exceptions.RequestException as e:
                    print(f"Błąd API Geolokalizacji: {e}")
            
            if user_agent_str:
                ua = parse(user_agent_str)
                enriched_data.update({'browser': f"{ua.browser.family} {ua.browser.version_string}" if ua.browser.family else "Unknown", 'os': f"{ua.os.family} {ua.os.version_string}" if ua.os.family else "Unknown", 'device_type': 'Telefon' if ua.is_mobile else 'Tablet' if ua.is_tablet else 'PC' if ua.is_pc else 'Inne'})

            new_active_session = ActiveSession(user_id=user.id, session_id=session_token, **enriched_data)
            new_history_entry = LoginHistory(user_id=user.id, **enriched_data)
            db.session.add(new_active_session)
            db.session.add(new_history_entry)
            db.session.commit()
            log_event(event_type='USER_LOGIN', details=f"Użytkownik '{user.username}' zalogował się pomyślnie.", actor_id=user.id)
            
            if not user.is_admin:
                if user.access_expires_at and user.access_expires_at < datetime.datetime.utcnow():
                    flash('Twój dostęp do aplikacji wygasł. Skontaktuj się z administratorem.', 'danger')
                    session.clear()
                    ActiveSession.query.filter_by(session_id=session_token).delete()
                    db.session.commit()
                    return redirect(url_for('login'))

            flash('Zostałeś pomyślnie zalogowany!', 'success')
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.datetime.utcnow()
            db.session.commit()
            log_details = f"Nieudana próba logowania na konto '{username}'. Próba #{user.failed_login_attempts}."
            log_event(event_type='LOGIN_FAILED', details=log_details, target_id=user.id)
            remaining_attempts = LOCKOUT_ATTEMPTS - user.failed_login_attempts
            if user.failed_login_attempts >= LOCKOUT_ATTEMPTS:
                 flash(f'Nieprawidłowe hasło. Konto zostało tymczasowo zablokowane na {LOCKOUT_TIME_MINUTES} minut z powodu zbyt wielu prób.', 'danger')
            elif remaining_attempts > 0:
                flash(f'Nieprawidłowe hasło. Pozostało prób: {remaining_attempts}.', 'warning')
            else:
                flash(f'Nieprawidłowe hasło. Konto zostało tymczasowo zablokowane.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        access_key_str = request.form.get('access_key')
        
        if not username or not password or not access_key_str:
            flash('Wszystkie pola są wymagane.', 'danger')
            return redirect(url_for('register'))
        if len(username) < 3:
            flash('Nazwa użytkownika musi mieć co najmniej 3 znaki.', 'danger')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('Hasło musi mieć co najmniej 6 znaków.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Ta nazwa użytkownika jest już zajęta.', 'danger')
            return redirect(url_for('register'))

        access_key = AccessKey.query.filter_by(key=access_key_str).first()
        if not access_key or access_key.status != 'aktywny':
            flash('Klucz dostępu jest nieprawidłowy, wykorzystany lub zablokowany.', 'danger')
            log_event('REGISTRATION_FAILED_KEY', f"Nieudana rejestracja użytkownika '{username}'. Problem z kluczem: '{access_key_str}'.")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        expiration_date = datetime.datetime.utcnow() + datetime.timedelta(days=access_key.validity_days)
        new_user = User(username=username, password_hash=hashed_password, access_expires_at=expiration_date, is_admin=False, is_blocked=False)
        db.session.add(new_user)
        db.session.flush()
        access_key.status = 'wykorzystany'
        access_key.used_by_user_id = new_user.id
        access_key.used_at = datetime.datetime.utcnow()
        db.session.add(access_key)
        log_event('USER_REGISTERED', f"Nowy użytkownik '{username}' zarejestrował się używając klucza '{access_key.key}'. Konto ważne do {expiration_date.strftime('%Y-%m-%d %H:%M')}.", target_id=new_user.id)
        db.session.commit()
        flash(f'Konto dla "{username}" zostało pomyślnie utworzone! Dostęp ważny przez {access_key.validity_days} dni.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    user_id_for_log = session.get('user_id')
    username_for_log = session.get('username', 'N/A')
    session_token_to_remove = session.get('session_token')
    if not session.get('is_impersonating'):
         log_event('USER_LOGOUT', f"Użytkownik '{username_for_log}' (ID: {user_id_for_log}) wylogował się.", actor_id=user_id_for_log)
    if session_token_to_remove:
        active_session_to_delete = ActiveSession.query.filter_by(session_id=session_token_to_remove, user_id=user_id_for_log).first()
        if active_session_to_delete:
            db.session.delete(active_session_to_delete)
            db.session.commit()
    session.clear()
    flash('Zostałeś pomyślnie wylogowany.', 'info')
    return redirect(url_for('index'))


# --- TRASY UŻYTKOWNIKA ---
@app.route('/dashboard')
@login_required
def dashboard():
    if g.user.is_admin and not session.get('is_impersonating'):
        return redirect(url_for('admin_dashboard'))
    user = g.user
    remaining_time = None
    if user.access_expires_at:
        now = datetime.datetime.utcnow()
        if user.access_expires_at > now:
            remaining_time = user.access_expires_at - now
    return render_template('dashboard.html', user=user, remaining_time=remaining_time)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        if form_type == 'profile':
            bio = request.form.get('bio', '')
            if len(bio) > 500:
                flash('Bio nie może przekraczać 500 znaków.', 'danger')
                return redirect(url_for('profile'))
            g.user.bio = bio
            if 'avatar' in request.files:
                file = request.files['avatar']
                if file.filename != '':
                    if allowed_file(file.filename):
                        if g.user.avatar and g.user.avatar != 'default.jpg':
                            old_avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], g.user.avatar)
                            if os.path.exists(old_avatar_path):
                                try:
                                    os.remove(old_avatar_path)
                                except OSError as e:
                                    print(f"Błąd podczas usuwania starego awatara: {e}")
                        try:
                            avatar_filename = save_avatar(file)
                            g.user.avatar = avatar_filename
                        except Exception as e_avatar:
                            flash(f'Błąd podczas zapisywania awatara: {str(e_avatar)}', 'danger')
                            log_event('AVATAR_UPLOAD_FAILED', f"Nieudany zapis awatara dla '{g.user.username}'. Błąd: {str(e_avatar)}")
                            return redirect(url_for('profile'))
                    else:
                        flash('Niedozwolony format pliku awatara. Dozwolone: JPG, PNG.', 'danger')
                        return redirect(url_for('profile'))
            db.session.commit()
            log_event('PROFILE_UPDATED', f"Użytkownik '{g.user.username}' zaktualizował swój profil.")
            flash('Twój profil został zaktualizowany.', 'success')
        elif form_type == 'password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            if not current_password or not new_password or not confirm_password:
                flash('Wszystkie pola hasła są wymagane.', 'danger')
                return redirect(url_for('profile'))
            if not check_password_hash(g.user.password_hash, current_password):
                flash('Obecne hasło jest nieprawidłowe.', 'danger')
            elif len(new_password) < 6:
                 flash('Nowe hasło musi mieć co najmniej 6 znaków.', 'danger')
            elif new_password != confirm_password:
                flash('Nowe hasła nie są identyczne.', 'danger')
            else:
                g.user.password_hash = generate_password_hash(new_password)
                db.session.commit()
                log_event('PASSWORD_CHANGED', f"Użytkownik '{g.user.username}' zmienił swoje hasło.")
                flash('Hasło zostało pomyślnie zmienione.', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html')

@app.route('/tickets')
@login_required
def tickets():
    user_tickets = Ticket.query.filter_by(user_id=g.user.id).order_by(Ticket.last_updated.desc()).all()
    return render_template('tickets.html', tickets=user_tickets)

@app.route('/tickets/new', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        subject = request.form.get('subject')
        message_text = request.form.get('message')
        if not subject or not message_text:
            flash('Temat i wiadomość są wymagane.', 'danger')
            return render_template('create_ticket.html')
        if len(subject) > 120 :
            flash('Temat jest za długi (maks. 120 znaków).', 'danger')
            return render_template('create_ticket.html', subject=subject, message=message_text)
        new_ticket = Ticket(user_id=g.user.id, subject=subject, status='Oczekujące')
        db.session.add(new_ticket)
        db.session.flush()
        first_message = TicketMessage(ticket_id=new_ticket.id, user_id=g.user.id, message=message_text)
        db.session.add(first_message)
        new_ticket.last_updated = datetime.datetime.utcnow()
        db.session.commit()
        log_event('TICKET_CREATED', f"Użytkownik '{g.user.username}' utworzył zgłoszenie #{new_ticket.id}: '{subject}'.", target_id=g.user.id)
        socketio.emit('new_ticket_event', {'ticket_id': new_ticket.id, 'subject': new_ticket.subject, 'user': new_ticket.user.username, 'timestamp': new_ticket.timestamp.strftime('%Y-%m-%d %H:%M')}, room='admins')
        flash('Twoje zgłoszenie zostało pomyślnie utworzone.', 'success')
        return redirect(url_for('view_ticket', ticket_id=new_ticket.id))
    return render_template('create_ticket.html')

@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def view_ticket(ticket_id):
    ticket_query = Ticket.query.filter_by(id=ticket_id)
    is_true_admin_not_impersonating = g.user.is_admin and not session.get('is_impersonating')
    if not is_true_admin_not_impersonating:
        ticket_query = ticket_query.filter_by(user_id=g.user.id)
    ticket = ticket_query.first_or_404()
    if request.method == 'POST':
        message_text = request.form.get('message')
        if not message_text:
            flash('Wiadomość nie może być pusta.', 'danger')
            return redirect(url_for('view_ticket', ticket_id=ticket.id))
        author_id = g.user.id 
        author_username = g.user.username
        author_is_admin = g.user.is_admin
        new_message = TicketMessage(ticket_id=ticket.id, user_id=author_id, message=message_text)
        db.session.add(new_message)
        ticket.last_updated = datetime.datetime.utcnow()
        if is_true_admin_not_impersonating:
            if request.form.get('close_ticket'):
                ticket.status = 'Zamknięte'
                log_event('TICKET_CLOSED', f"Admin '{author_username}' zamknął zgłoszenie #{ticket.id}.", actor_id=author_id, target_id=ticket.user_id)
                socketio.emit('ticket_status_changed', {'ticket_id': ticket.id, 'status': 'Zamknięte'}, room=f'user_{ticket.user_id}')
                socketio.emit('ticket_status_changed', {'ticket_id': ticket.id, 'status': 'Zamknięte'}, room='admins')
            else:
                if ticket.status != 'Zamknięte':
                    ticket.status = 'Odpowiedziano'
                    socketio.emit('ticket_status_changed', {'ticket_id': ticket.id, 'status': 'Odpowiedziano'}, room=f'user_{ticket.user_id}')
                    socketio.emit('ticket_status_changed', {'ticket_id': ticket.id, 'status': 'Odpowiedziano'}, room='admins')
        else:
            if ticket.status != 'Zamknięte':
                ticket.status = 'Oczekujące'
                socketio.emit('ticket_status_changed', {'ticket_id': ticket.id, 'status': 'Oczekujące'}, room='admins')
                socketio.emit('ticket_status_changed', {'ticket_id': ticket.id, 'status': 'Oczekujące'}, room=f'user_{ticket.user_id}')
        db.session.commit()
        log_event('TICKET_REPLIED', f"Nowa odpowiedź w zgłoszeniu #{ticket.id} od '{author_username}'.", actor_id=author_id, target_id=ticket.user_id)
        message_data_for_socket = {'message': nl2br_filter(new_message.message), 'user': author_username, 'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M'), 'is_admin': author_is_admin, 'ticket_id': ticket.id}
        if is_true_admin_not_impersonating:
            if ticket.user_id != author_id :
                 socketio.emit('new_message_event', message_data_for_socket, room=f'user_{ticket.user_id}')
        else:
            socketio.emit('new_message_event', message_data_for_socket, room='admins')
        flash('Twoja odpowiedź została dodana.', 'success')
        return redirect(url_for('view_ticket', ticket_id=ticket.id))
    return render_template('view_ticket.html', ticket=ticket)


# --- NOWY ENDPOINT DLA AJAX UPLOAD ---
@app.route('/ajax_upload_video', methods=['POST'])
@login_required
def ajax_upload_video():
    if 'video_file' not in request.files:
        print("--- AJAX UPLOAD: Brak 'video_file' w request.files ---")
        return jsonify({'success': False, 'message': 'Nie wybrano pliku wideo.'}), 400
    
    file = request.files['video_file']
    if file.filename == '':
        print("--- AJAX UPLOAD: Pusta nazwa pliku ---")
        return jsonify({'success': False, 'message': 'Nie wybrano pliku wideo (pusta nazwa).'}), 400

    if file and allowed_video_file(file.filename):
        file.seek(0, os.SEEK_END)
        file_length = file.tell()
        file.seek(0)
        
        if file_length > app.config['MAX_VIDEO_FILE_SIZE']:
            print(f"--- AJAX UPLOAD: Plik za duży. Rozmiar: {file_length} > {app.config['MAX_VIDEO_FILE_SIZE']} ---")
            return jsonify({'success': False, 'message': f"Plik jest za duży. Maksymalny rozmiar to {app.config['MAX_VIDEO_FILE_SIZE']//(1024*1024)} MB."}), 413

        original_filename = secure_filename(file.filename)
        unique_id = uuid.uuid4().hex
        server_filename = f"{unique_id}_{original_filename}"
        upload_filepath = os.path.join(app.config['UPLOAD_VIDEO_FOLDER'], server_filename)

        try:
            print(f"--- AJAX UPLOAD: Próba zapisu pliku '{original_filename}' jako '{server_filename}' do '{upload_filepath}' ---")
            file.save(upload_filepath)
            
            if os.path.exists(upload_filepath):
                print(f"--- AJAX UPLOAD: Plik '{server_filename}' zapisany pomyślnie. Rozmiar: {os.path.getsize(upload_filepath)} ---")
                log_event('VIDEO_PRE_UPLOADED', f"Użytkownik '{g.user.username}' wstępnie przesłał plik: {original_filename} (zapisany jako {server_filename}).", actor_id=g.user.id)
                return jsonify({'success': True, 'server_filename': server_filename, 'message': 'Plik przesłany.'})
            else:
                print(f"--- AJAX UPLOAD: BŁĄD KRYTYCZNY - Plik '{server_filename}' NIE ISTNIEJE po zapisie! ---")
                log_event('VIDEO_PRE_UPLOAD_FAILED', f"Krytyczny błąd zapisu pliku {original_filename} (jako {server_filename}) dla '{g.user.username}'. Plik nie istnieje po save().", actor_id=g.user.id)
                return jsonify({'success': False, 'message': 'Błąd serwera podczas zapisywania pliku.'}), 500
        except Exception as e:
            print(f"--- AJAX UPLOAD: WYJĄTEK podczas zapisu pliku '{server_filename}'. Błąd: {str(e)} ---")
            log_event('VIDEO_PRE_UPLOAD_FAILED', f"Nieudany zapis pliku {original_filename} (jako {server_filename}) dla '{g.user.username}'. Błąd: {e}", actor_id=g.user.id)
            return jsonify({'success': False, 'message': f'Nie udało się zapisać pliku: {e}'}), 500
    else:
        print(f"--- AJAX UPLOAD: Niedozwolony format pliku lub błąd pliku. Nazwa: {file.filename} ---")
        return jsonify({'success': False, 'message': 'Niedozwolony format pliku lub problem z plikiem.'}), 400


# --- TRASA GENERACJI WIDEO (ZMODYFIKOWANA) ---
@app.route('/generation', methods=['GET', 'POST'])
@login_required
def generation():
    if request.method == 'POST':
        server_filename = request.form.get('server_video_filename')

        if not server_filename:
            flash('Brak informacji o przesłanym pliku wideo. Spróbuj wybrać plik ponownie.', 'danger')
            print("--- GENERATE: Brak 'server_video_filename' w danych formularza ---")
            return jsonify({'success': False, 'message': 'Brak informacji o przesłanym pliku.'}), 400
        
        server_filename = secure_filename(server_filename)
        input_filepath = os.path.join(app.config['UPLOAD_VIDEO_FOLDER'], server_filename)

        print(f"--- GENERATE: Rozpoczynanie przetwarzania dla pliku (już na serwerze): {input_filepath} ---")

        if not os.path.exists(input_filepath):
            flash(f'Błąd: Oczekiwany plik {server_filename} nie został znaleziony na serwerze. Proszę przesłać go ponownie.', 'danger')
            print(f"--- GENERATE: BŁĄD KRYTYCZNY - Oczekiwany plik {input_filepath} NIE ISTNIEJE! ---")
            log_event('VIDEO_PROCESSING_ERROR', f"Plik {server_filename} nie znaleziony na serwerze przed przetworzeniem dla '{g.user.username}'.", actor_id=g.user.id)
            return jsonify({'success': False, 'message': 'Błąd: Nie znaleziono pliku wejściowego na serwerze.'}), 500

        settings = {
            'stabilizacja_enabled': 'stabilizacja_enabled' in request.form,
            'stabilizacja_smoothing': int(request.form.get('stabilizacja_smoothing', 10)),
            'stabilizacja_zoom': int(request.form.get('stabilizacja_zoom', 0)),
            'przysp_wideo_enabled': 'przysp_wideo_enabled' in request.form,
            'przysp_wideo_percent': int(request.form.get('przysp_wideo_value', 3)),
            'odbicie_lustrzane_enabled': 'odbicie_lustrzane_enabled' in request.form,
            'obrot_wideo_enabled': 'obrot_wideo_enabled' in request.form,
            'obrot_wideo_degrees': int(request.form.get('obrot_wideo_value', 1)),
            'crop_wideo_enabled': 'crop_wideo_enabled' in request.form,
            'crop_wideo_pixels': int(request.form.get('crop_wideo_value', 10)),
            'jasnosc_enabled': 'jasnosc_enabled' in request.form,
            'jasnosc_value': int(request.form.get('jasnosc_value', 2)),
            'kontrast_enabled': 'kontrast_enabled' in request.form,
            'kontrast_value': int(request.form.get('kontrast_value', 15)),
            'nasycenie_enabled': 'nasycenie_enabled' in request.form,
            'nasycenie_value': int(request.form.get('nasycenie_value', 5)),
            'gamma_enabled': 'gamma_enabled' in request.form,
            'gamma_value': int(request.form.get('gamma_value', 10)),
            'hue_enabled': 'hue_enabled' in request.form,
            'hue_degrees': int(request.form.get('hue_value', 10)),
            'curves_strong_contrast_enabled': 'curves_strong_contrast_enabled' in request.form,
            'szum_enabled': 'szum_enabled' in request.form,
            'szum_alls': int(request.form.get('szum_value', 5)),
            'gblur_enabled': 'gblur_enabled' in request.form,
            'gblur_sigma_ui': int(request.form.get('gblur_sigma', 30)),
            'boxblur_enabled': 'boxblur_enabled' in request.form,
            'boxblur_luma_radius': int(request.form.get('boxblur_luma_radius', 2)),
            'unsharp_enabled': 'unsharp_enabled' in request.form,
            'unsharp_luma_msize': int(request.form.get('unsharp_luma_msize', 5)),
            'unsharp_luma_amount': float(request.form.get('unsharp_luma_amount', 1.5)),
            'colorbalance_shadows_enabled': 'colorbalance_shadows_enabled' in request.form,
            'colorbalance_shadows_rs_ui': float(request.form.get('colorbalance_shadows_rs', 0.3)),
            'motion_blur_enabled': 'motion_blur_enabled' in request.form,
            'lenscorrection_enabled': 'lenscorrection_enabled' in request.form,
            'lenscorrection_k1k2_ui': int(request.form.get('lenscorrection_k1k2', 2)),
            'vignette_enabled': 'vignette_enabled' in request.form,
            'fade_in_enabled': 'fade_in_enabled' in request.form,
            'fade_in_nb_frames': int(request.form.get('fade_in_nb_frames', 30)),
            'fade_out_enabled': 'fade_out_enabled' in request.form,
            'fade_out_nb_frames': int(request.form.get('fade_out_nb_frames', 30)),
            'hqdn3d_enabled': 'hqdn3d_enabled' in request.form,
            'audio_prep_enabled': 'audio_prep_enabled' in request.form,
            'audio_prep_silence_duration': float(request.form.get('audio_prep_silence_duration', 1.5)),
            'przysp_audio_enabled': 'przysp_audio_enabled' in request.form,
            'przysp_audio_percent': int(request.form.get('przysp_audio_value', 3)),
        }

        unique_id_from_filename = server_filename.split('_')[0]
        original_filename_part = '_'.join(server_filename.split('_')[1:])
        output_filename_on_server = f"processed_{unique_id_from_filename}_{secure_filename(os.path.splitext(original_filename_part)[0])}.mp4"
        output_filepath = os.path.join(app.config['GENERATED_VIDEO_FOLDER'], output_filename_on_server)
        
        print(f"--- GENERATE: Ustawienia zebrane, plik wyjściowy: {output_filepath} ---")

        try:
            success, message_or_path = process_video_ffmpeg(input_filepath, output_filepath, settings)
            
            if os.path.exists(input_filepath):
                 try:
                    os.remove(input_filepath)
                    print(f"--- GENERATE: Usunięto plik wejściowy {input_filepath} z folderu uploads. ---")
                 except OSError as e_rem_inp:
                    print(f"--- GENERATE: Nie udało się usunąć pliku wejściowego {input_filepath}: {e_rem_inp} ---")

            if success:
                log_event('VIDEO_PROCESSED', f"Użytkownik '{g.user.username}' przetworzył plik: {server_filename}. Wynik: {output_filename_on_server}", actor_id=g.user.id)
                download_url = url_for('download_generated_video', filename=output_filename_on_server, _external=True)
                print(f"--- GENERATE: Przetwarzanie zakończone sukcesem. Link do pobrania: {download_url} ---")
                return jsonify({'success': True, 'download_url': download_url, 'message': 'Przetwarzanie zakończone!'})
            else:
                log_event('VIDEO_PROCESSING_FAILED', f"Błąd przetwarzania pliku {server_filename} dla '{g.user.username}'. Błąd: {message_or_path}", actor_id=g.user.id)
                print(f"--- GENERATE: Błąd przetwarzania FFmpeg: {message_or_path} ---")
                return jsonify({'success': False, 'message': f'Błąd przetwarzania: {message_or_path}'}), 500
        except Exception as e_proc:
            import traceback
            traceback.print_exc()
            log_event('VIDEO_PROCESSING_ERROR', f"Krytyczny błąd przetwarzania pliku {server_filename} dla '{g.user.username}'. Błąd: {str(e_proc)}", actor_id=g.user.id)
            if os.path.exists(input_filepath):
                try:
                    os.remove(input_filepath)
                except OSError as e_rem_inp_err:
                    print(f"--- GENERATE: Nie udało się usunąć pliku wejściowego {input_filepath} po błędzie: {e_rem_inp_err} ---")
            print(f"--- GENERATE: Krytyczny wyjątek podczas process_video_ffmpeg: {str(e_proc)} ---")
            return jsonify({'success': False, 'message': f'Wewnętrzny błąd serwera podczas przetwarzania: {str(e_proc)}'}), 500

    max_video_size_mb = app.config.get('MAX_VIDEO_FILE_SIZE', 100 * 1024 * 1024) // (1024 * 1024)
    return render_template('generation.html', max_video_size_mb=max_video_size_mb)

@app.route('/generated_video/<path:filename>')
@login_required # Zakładam, że ten dekorator @login_required jest zdefiniowany w Twoim kodzie
def download_generated_video(filename):
    # Używamy secure_filename tak jak w Twojej oryginalnej funkcji, aby oczyścić nazwę pliku
    safe_filename = secure_filename(filename)
    
    directory = app.config.get('GENERATED_VIDEO_FOLDER') 
    
    # Sprawdzenie, czy konfiguracja folderu jest poprawna
    if not directory:
        print(f"--- DOWNLOAD ERROR: Klucz 'GENERATED_VIDEO_FOLDER' nie jest ustawiony w app.config! ---")
        # Możesz dodać logowanie do AuditLog, jeśli masz taką funkcję
        # np. log_event('DOWNLOAD_CONFIG_ERROR', 'Klucz GENERATED_VIDEO_FOLDER nie jest ustawiony')
        flash("Błąd konfiguracji serwera uniemożliwia pobranie pliku.", "danger")
        return redirect(url_for('generation')) # Przekieruj gdzieś sensownie

    # Jeśli oryginalna nazwa pliku różni się od "bezpiecznej" nazwy, obsłuż to tak jak w Twoim kodzie
    if safe_filename != filename:
        print(f"--- DOWNLOAD SECURITY WARNING: Oryginalna nazwa pliku '{filename}' została oczyszczona do '{safe_filename}' ---")
        # Poniżej jest logika z Twojej oryginalnej funkcji dla tego przypadku
        log_event('DOWNLOAD_SECURITY_ISSUE', f"Potencjalny problem z bezpieczeństwem przy pobieraniu pliku: oryginalny '{filename}', bezpieczny '{safe_filename}' przez '{g.user.username if hasattr(g, 'user') and g.user and hasattr(g.user, 'username') else 'N/A'}'", actor_id=g.user.id if hasattr(g, 'user') and g.user else None)
        flash('Nieprawidłowa nazwa pliku (potencjalnie niebezpieczne znaki).', 'danger')
        return redirect(url_for('generation')) # Lub inny odpowiedni redirect

    filepath = os.path.join(directory, safe_filename) # Używamy bezpiecznej nazwy do tworzenia ścieżki

    print(f"--- DOWNLOAD ATTEMPT ---")
    user_display = "Niezidentyfikowany użytkownik" # Domyślna wartość
    if hasattr(g, 'user') and g.user:
        if hasattr(g.user, 'username') and g.user.username:
            user_display = g.user.username
        elif hasattr(g.user, 'id'): 
            user_display = f"Użytkownik ID: {g.user.id}"
    
    print(f"--- User attempting download: {user_display} ---")
    print(f"--- Requested filename (original): {filename} ---")
    print(f"--- Requested filename (sanitized for path): {safe_filename} ---")
    print(f"--- Serving directory configured as: {app.config.get('GENERATED_VIDEO_FOLDER', 'NOT SET')} ---")
    print(f"--- Absolute serving directory path: {directory} ---")
    print(f"--- Absolute filepath on server for download: {filepath} ---")
    
    dir_exists = os.path.exists(directory)
    file_exists = os.path.exists(filepath)

    print(f"--- Does serving directory exist? ({directory}): {dir_exists} ---")
    print(f"--- Does file exist? ({filepath}): {file_exists} ---")
    
    if dir_exists:
        try:
            dir_contents = os.listdir(directory)
            print(f"--- Contents of directory ({directory}): {dir_contents} ---")
            if safe_filename not in dir_contents and file_exists:
                    print(f"--- WARNING: Sanitized filename '{safe_filename}' not in os.listdir output but os.path.exists IS True. ---")
            elif safe_filename not in dir_contents and not file_exists:
                    print(f"--- ERROR: Sanitized filename '{safe_filename}' is NOT in directory listing AND os.path.exists is False. ---")
        except Exception as e_listdir:
            print(f"--- ERROR listing directory contents ({directory}): {e_listdir} ---")
    else:
        print(f"--- ERROR: Serving directory ({directory}) does NOT exist! Cannot serve file. ---")
        log_event('DOWNLOAD_ERROR', f"Serving directory {directory} does not exist for user {user_display}, requested {filename}", actor_id=g.user.id if hasattr(g,'user') and g.user else None)
        flash(f"Błąd konfiguracji: Katalog do pobierania '{directory}' nie istnieje.", "danger")
        return redirect(url_for('generation'))

    if not file_exists:
        print(f"--- ERROR: File ({filepath}) does NOT exist! Cannot send. ---")
        log_event('DOWNLOAD_ERROR_FILE_NOT_FOUND', f"File {filepath} does not exist for user {user_display}, requested {filename}", actor_id=g.user.id if hasattr(g,'user') and g.user else None)
        flash(f"Błąd: Plik '{safe_filename}' nie został znaleziony.", "danger")
        # Dla debugowania, pokażmy zawartość katalogu, jeśli istnieje
        if dir_exists:
            # dir_contents_str = ", ".join(os.listdir(directory)) if os.path.exists(directory) else 'nie można wylistować katalogu'
            # flash(f"Dostępne pliki: {dir_contents_str}", "info") # Można odkomentować dla debugowania na stronie
            pass
        return redirect(url_for('generation'))

    try:
        print(f"--- Attempting to send file: {filepath} (using sanitized filename for send_from_directory: '{safe_filename}') ---")
        # send_from_directory oczekuje nazwy pliku względnej do 'directory'
        return send_from_directory(directory, safe_filename, as_attachment=True)
    except Exception as e:
        print(f"--- DOWNLOAD ERROR during send_from_directory for {filepath}: {e} ---")
        print(f"--- Full traceback: ---")
        print(traceback.format_exc()) # To wydrukuje pełny traceback błędu w logach Render
        log_event('DOWNLOAD_ERROR_SENDFILE', f"Exception during send_from_directory for {filepath}, user {user_display}. Error: {str(e)}", actor_id=g.user.id if hasattr(g,'user') and g.user else None)
        flash("Wystąpił błąd serwera podczas próby pobrania pliku. Proszę sprawdzić logi serwera.", "danger")
        return redirect(url_for('generation'))


# --- TRASY PANELU ADMINA ---
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    user_count = User.query.count()
    session_count = ActiveSession.query.count()
    keys_count = AccessKey.query.count()
    alerts = AuditLog.query.filter(AuditLog.event_type == 'NEW_DEVICE_LOGIN').order_by(AuditLog.timestamp.desc()).limit(5).all()
    return render_template('admin/dashboard.html', user_count=user_count, session_count=session_count, keys_count=keys_count, alerts=alerts)

@app.route('/admin/tickets')
@admin_required
@limiter.exempt
def admin_tickets():
    status = request.args.get('status', 'oczekujace')
    query = Ticket.query
    if status == 'oczekujace':
        query = query.filter(Ticket.status == 'Oczekujące')
    elif status == 'odpowiedziano':
        query = query.filter(Ticket.status == 'Odpowiedziano')
    elif status == 'zamkniete':
        query = query.filter(Ticket.status == 'Zamknięte')
    all_tickets = query.order_by(Ticket.last_updated.desc()).all()
    return render_template('admin/tickets.html', tickets=all_tickets, current_status=status)

@app.route('/admin/keys', methods=['GET', 'POST'])
@admin_required
def admin_keys():
    if request.method == 'POST':
        try:
            validity_str = request.form.get('validity')
            if not validity_str:
                flash('Okres ważności jest wymagany.', 'danger')
                return redirect(url_for('admin_keys'))
            validity = int(validity_str)
            if validity not in [7, 30]:
                flash('Nieprawidłowy okres ważności. Dozwolone: 7 lub 30 dni.', 'danger')
            else:
                new_key_str = secrets.token_hex(16)
                new_key_obj = AccessKey(key=new_key_str, validity_days=validity, status='aktywny')
                db.session.add(new_key_obj)
                admin_username = session.get('original_user_username', session.get('username', 'System'))
                log_event('KEY_GENERATED', f"Admin '{admin_username}' wygenerował klucz '{new_key_str}' na {validity} dni.")
                db.session.commit()
                flash(f'Wygenerowano nowy klucz na {validity} dni: {new_key_str}', 'success')
        except ValueError:
            flash('Nieprawidłowa wartość dla okresu ważności.', 'danger')
        except Exception as e_key:
            flash(f'Wystąpił błąd podczas generowania klucza: {str(e_key)}', 'danger')
            log_event('KEY_GENERATION_FAILED', f"Nieudane generowanie klucza. Błąd: {str(e_key)}")
        return redirect(url_for('admin_keys'))
    keys = AccessKey.query.order_by(AccessKey.created_at.desc()).all()
    return render_template('admin/keys.html', keys=keys)

@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.id.asc()).all()
    now = datetime.datetime.utcnow()
    return render_template('admin/users.html', users=users, now=now)

@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('admin/user_detail.html', user=user)

@app.route('/admin/user/block/<int:user_id>', methods=['POST'])
@admin_required
def block_user(user_id):
    user_to_block = User.query.get_or_404(user_id)
    admin_username = session.get('original_user_username', session.get('username', 'N/A'))
    if user_to_block.is_admin:
        flash('Nie można zablokować konta administratora.', 'danger')
    elif user_to_block.id == session.get('original_user_id', session.get('user_id')):
        flash('Nie możesz zablokować własnego konta.', 'danger')
    else:
        user_to_block.is_blocked = True
        ActiveSession.query.filter_by(user_id=user_to_block.id).delete()
        if user_to_block.used_key:
            associated_key = AccessKey.query.filter_by(id=user_to_block.used_key.id).first()
            if associated_key:
                 associated_key.status = 'zablokowany'
        db.session.commit()
        log_event(event_type='USER_BLOCKED', details=f"Admin '{admin_username}' zablokował użytkownika '{user_to_block.username}'.", target_id=user_to_block.id)
        flash(f'Użytkownik {user_to_block.username} został zablokowany. Wszystkie jego sesje zostały zakończone.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/unblock/<int:user_id>', methods=['POST'])
@admin_required
def unblock_user(user_id):
    user_to_unblock = User.query.get_or_404(user_id)
    admin_username = session.get('original_user_username', session.get('username', 'N/A'))
    user_to_unblock.is_blocked = False
    if user_to_unblock.used_key:
        associated_key = AccessKey.query.filter_by(id=user_to_unblock.used_key.id).first()
        if associated_key and associated_key.status == 'zablokowany':
            associated_key.status = 'wykorzystany'
    db.session.commit()
    log_event(event_type='USER_UNBLOCKED', details=f"Admin '{admin_username}' odblokował użytkownika '{user_to_unblock.username}'.", target_id=user_to_unblock.id)
    flash(f'Użytkownik {user_to_unblock.username} został odblokowany.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user_to_edit = User.query.get_or_404(user_id)
    admin_username = session.get('original_user_username', session.get('username', 'N/A'))
    if user_to_edit.is_admin and user_to_edit.id != session.get('original_user_id', session.get('user_id')):
        flash('Nie można edytować danych innego administratora w ten sposób.', 'danger')
        return redirect(url_for('admin_users'))
    if request.method == 'POST':
        new_expiry_date_str = request.form.get('access_expires_at')
        if new_expiry_date_str:
            try:
                new_expiry_date = datetime.datetime.strptime(new_expiry_date_str, '%Y-%m-%dT%H:%M')
                user_to_edit.access_expires_at = new_expiry_date
                db.session.commit()
                log_event(event_type='USER_ACCESS_EDITED', details=f"Admin '{admin_username}' zmienił datę wygaśnięcia dostępu dla '{user_to_edit.username}' na {new_expiry_date_str}.", target_id=user_to_edit.id)
                flash('Data wygaśnięcia konta została zaktualizowana.', 'success')
            except ValueError:
                flash('Nieprawidłowy format daty. Użyj formatu RRRR-MM-DDTHH:MM.', 'danger')
        else:
            user_to_edit.access_expires_at = None
            db.session.commit()
            log_event(event_type='USER_ACCESS_EDITED', details=f"Admin '{admin_username}' usunął limit czasowy dla konta '{user_to_edit.username}'.", target_id=user_to_edit.id)
            flash('Usunięto limit czasowy dla konta (dostęp nieograniczony czasowo).', 'success')
        return redirect(url_for('admin_user_detail', user_id=user_id))
    return render_template('admin/edit_user.html', user=user_to_edit)

@app.route('/admin/session/terminate/<int:active_session_id>', methods=['POST'])
@admin_required
def terminate_session(active_session_id):
    session_to_terminate = ActiveSession.query.get_or_404(active_session_id)
    user_id_of_session = session_to_terminate.user_id
    admin_username = session.get('original_user_username', session.get('username', 'N/A'))
    db.session.delete(session_to_terminate)
    db.session.commit()
    log_event(event_type='SESSION_TERMINATED', details=f"Admin '{admin_username}' zdalnie zakończył sesję (ID: {active_session_id}) dla użytkownika o ID {user_id_of_session}.", target_id=user_id_of_session)
    flash('Wybrana sesja została zakończona.', 'success')
    return redirect(url_for('admin_user_detail', user_id=user_id_of_session))

@app.route('/admin/audit-log')
@admin_required
def audit_log():
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=25, error_out=False)
    return render_template('admin/audit_log.html', logs=logs)

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    admin_username = session.get('original_user_username', session.get('username', 'N/A'))
    if request.method == 'POST':
        try:
            lockout_attempts_str = request.form.get('LOCKOUT_ATTEMPTS')
            lockout_time_str = request.form.get('LOCKOUT_TIME_MINUTES')
            if not lockout_attempts_str or not lockout_time_str:
                flash('Wszystkie pola ustawień są wymagane.', 'danger')
                return redirect(url_for('admin_settings'))
            settings_to_update = {'LOCKOUT_ATTEMPTS': int(lockout_attempts_str), 'LOCKOUT_TIME_MINUTES': int(lockout_time_str)}
            validation_passed = True
            for key, value in settings_to_update.items():
                if value < 1:
                    flash(f'Wartość dla {key} musi być co najmniej 1.', 'danger')
                    validation_passed = False
            if validation_passed:
                for key, value in settings_to_update.items():
                    setting = SystemSetting.query.get(key)
                    if setting:
                        setting.value = str(value)
                    else:
                        setting = SystemSetting(key=key, value=str(value))
                        db.session.add(setting)
                db.session.commit()
                log_event('SETTINGS_CHANGED', f"Admin '{admin_username}' zaktualizował ustawienia systemu: {settings_to_update}.")
                flash('Ustawienia systemu zostały pomyślnie zapisane.', 'success')
        except ValueError:
            flash('Wprowadzono nieprawidłowe wartości liczbowe dla ustawień.', 'danger')
        except Exception as e_settings:
            flash(f'Wystąpił nieoczekiwany błąd podczas zapisywania ustawień: {str(e_settings)}', 'danger')
            log_event('SETTINGS_CHANGE_FAILED', f"Nieudana zmiana ustawień. Błąd: {str(e_settings)}")
        return redirect(url_for('admin_settings'))
    settings_from_db = SystemSetting.query.all()
    current_settings = {s.key: s.value for s in settings_from_db}
    current_settings.setdefault('LOCKOUT_ATTEMPTS', '5')
    current_settings.setdefault('LOCKOUT_TIME_MINUTES', '5')
    return render_template('admin/settings.html', settings=current_settings)

@app.route('/admin/user/impersonate/<int:user_id>')
@admin_required
def impersonate_user(user_id):
    if session.get('is_impersonating'):
        flash('Już wcielasz się w innego użytkownika. Najpierw zakończ obecną sesję wcielania.', 'warning')
        return redirect(url_for('admin_users'))
    user_to_impersonate = User.query.get_or_404(user_id)
    if user_to_impersonate.id == session['user_id'] and session['is_admin']:
        flash('Nie możesz wcielić się w samego siebie.', 'info')
        return redirect(url_for('admin_users'))
    if user_to_impersonate.is_admin:
        flash('Nie można wcielić się w innego administratora.', 'danger')
        return redirect(url_for('admin_users'))
    original_admin_id = session['user_id']
    original_admin_username = session['username']
    original_admin_session_token = session.get('session_token')
    if original_admin_session_token:
        ActiveSession.query.filter_by(session_id=original_admin_session_token, user_id=original_admin_id).delete()
        db.session.commit()
    session['user_id'] = user_to_impersonate.id
    session['username'] = user_to_impersonate.username
    session['is_admin'] = user_to_impersonate.is_admin
    session['is_impersonating'] = True
    session['original_user_id'] = original_admin_id
    session['original_user_username'] = original_admin_username
    session.pop('session_token', None)
    log_event('USER_IMPERSONATE_START', f"Admin '{original_admin_username}' (ID: {original_admin_id}) wcielił się w użytkownika '{user_to_impersonate.username}' (ID: {user_to_impersonate.id}).", actor_id=original_admin_id, target_id=user_to_impersonate.id)
    flash(f'Pomyślnie wcielono się w użytkownika {user_to_impersonate.username}.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/user/stop_impersonating')
@login_required
def stop_impersonating():
    if not session.get('is_impersonating'):
        return redirect(url_for('dashboard'))
    impersonated_user_username = session.get('username', 'N/A')
    impersonated_user_id = session.get('user_id')
    original_admin_id = session.pop('original_user_id', None)
    original_admin_username = session.pop('original_user_username', None)
    session.pop('is_impersonating', None)
    if not original_admin_id or not original_admin_username:
        session.clear()
        flash('Błąd krytyczny sesji podczas kończenia wcielania. Zostałeś wylogowany.', 'danger')
        return redirect(url_for('login'))
    admin_user = User.query.get(original_admin_id)
    if not admin_user:
        session.clear()
        flash('Nie można przywrócić sesji administratora. Konto mogło zostać usunięte.', 'danger')
        return redirect(url_for('login'))
    session['user_id'] = admin_user.id
    session['username'] = admin_user.username
    session['is_admin'] = admin_user.is_admin
    new_admin_session_token = secrets.token_hex(24)
    session['session_token'] = new_admin_session_token
    ip_addr = request.remote_addr
    user_agent_str = request.headers.get('User-Agent', 'Unknown')
    enriched_data = {"ip_address": ip_addr, "user_agent_raw": user_agent_str}
    new_active_admin_session = ActiveSession(user_id=admin_user.id, session_id=new_admin_session_token, **enriched_data)
    db.session.add(new_active_admin_session)
    db.session.commit()
    log_event('USER_IMPERSONATE_STOP', f"Admin '{original_admin_username}' (ID: {original_admin_id}) zakończył wcielanie się w użytkownika '{impersonated_user_username}' (ID: {impersonated_user_id}).", actor_id=original_admin_id)
    flash(f'Powrócono do konta administratora: {original_admin_username}.', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/search')
@admin_required
def admin_search():
    query_str = request.args.get('q', '').strip()
    if not query_str:
        return redirect(url_for('admin_dashboard'))
    users_found = User.query.filter(User.username.ilike(f'%{query_str}%')).all()
    ticket_id_search = None
    if query_str.isdigit():
        ticket_id_search = int(query_str)
    tickets_found = Ticket.query.filter(or_(Ticket.subject.ilike(f'%{query_str}%'), Ticket.id == ticket_id_search if ticket_id_search is not None else False)).all()
    keys_found = AccessKey.query.filter(AccessKey.key.ilike(f'%{query_str}%')).all()
    log_event('ADMIN_SEARCH', f"Admin '{g.user.username}' wyszukał frazę: '{query_str}'. Znaleziono: {len(users_found)}U, {len(tickets_found)}T, {len(keys_found)}K.")
    return render_template('admin/search_results.html', query=query_str, users=users_found, tickets=tickets_found, keys=keys_found)


# --- ZDARZENIA SOCKET.IO ---
@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        return False
    user = User.query.get(session['user_id'])
    if not user: return False
    if user.is_admin and not session.get('is_impersonating'):
        join_room('admins')
        print(f"Admin {user.username} dołączył do pokoju 'admins'. SID: {request.sid}")
    else:
        join_room(f'user_{user.id}')
        print(f"Użytkownik {user.username} (ID: {user.id}) dołączył do pokoju 'user_{user.id}'. SID: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Klient odłączony. SID: {request.sid}")
    pass


# --- KOMENDY CLI I URUCHAMIANIE ---
@app.cli.command("create-admin")
@click.option('--username', default="admin", help="Nazwa użytkownika administratora.")
@click.option('--password', default="admin", help="Hasło administratora.")
def create_admin(username, password):
    if User.query.filter_by(username=username).first():
        print(f"Konto administratora '{username}' już istnieje.")
        return
    hashed_password = generate_password_hash(password)
    new_admin = User(username=username, password_hash=hashed_password, is_admin=True, access_expires_at=None, is_blocked=False)
    db.session.add(new_admin)
    db.session.commit()
    print(f"Konto administratora '{username}' z hasłem '{password}' zostało utworzone.")

@app.cli.command("init-db")
def init_db_command():
    db.create_all()
    default_settings = {'LOCKOUT_ATTEMPTS': '5', 'LOCKOUT_TIME_MINUTES': '5'}
    for key, value in default_settings.items():
        if not SystemSetting.query.get(key):
            db.session.add(SystemSetting(key=key, value=value))
    db.session.commit()
    print("Baza danych została zainicjalizowana, a domyślne ustawienia systemowe zostały dodane/sprawdzone.")


if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)