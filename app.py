import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
import mysql.connector
import requests
import uuid
import random
from datetime import datetime, timedelta
from functools import wraps
from flask_wtf.csrf import CSRFProtect
from flask import jsonify



app = Flask(__name__)
app.secret_key = 'SECRET_KEY'  # Szükséges a session kezeléshez
app.permanent_session_lifetime = timedelta(days=7)  # Session expires after 7 days
app.config['SECRET_KEY'] = 'SECRET_KEY'
app.config['RECAPTCHA_SECRET_KEY'] = 'CAPTCHA'
app.config['WTF_CSRF_ENABLED'] = True
csrf = CSRFProtect(app)
# MySQL kapcsolódás (auto-reconnect hozzáadása)
db = None  # Initialize db as None to make it globally accessible

def get_db_connection():
    global db
    if db is None or not db.is_connected():
        db = mysql.connector.connect(
            host="localhost",
            user="username",
            password="password",
            database="mydatabase"
        )
    return db
def verify_recaptcha(recaptcha_response):
    if not recaptcha_response:
        return False
    
    verify_response = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        data={
            'secret': app.config['RECAPTCHA_SECRET_KEY'],
            'response': recaptcha_response
        }
    )
    
    verify_data = verify_response.json()
    return verify_data.get('success', False)
db = get_db_connection()


def log_user_ip(user_id, action_type):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get IP address - check for proxies first
        if request.headers.get('X-Forwarded-For'):
            ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        else:
            ip_address = request.remote_addr
        
        cursor.execute("""
            INSERT INTO user_ip_logs (user_id, ip_address, action_type)
            VALUES (%s, %s, %s)
        """, (user_id, ip_address, action_type))
        
        conn.commit()
    except Exception as e:
        print(f"Error logging IP: {str(e)}")
    finally:
        if conn:
            conn.close()

def is_license_valid(license_data):
    """Check if a license is valid (active and not expired)"""
    if not license_data or not license_data.get('active'):
        return False
    
    # Check expiration date if it exists
    expires_at = license_data.get('expires_at')
    if expires_at and expires_at < datetime.now():
        return False
        
    return True


def log_user_activity(user_id=None, username=None, activity_type='unknown', status='success', details=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get IP address - check for proxies first
        if request.headers.get('X-Forwarded-For'):
            ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        else:
            ip_address = request.remote_addr
        
        cursor.execute("""
            INSERT INTO user_activity_logs 
            (user_id, username, ip_address, activity_type, status, details, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
        """, (user_id, username, ip_address, activity_type, status, details))
        
        conn.commit()
    except Exception as e:
        print(f"Error logging activity: {str(e)}")
    finally:
        if conn:
            conn.close()

def close_db_connection(conn=None, cursor=None):
    if cursor:
        cursor.close()

# HWID generálás minden böngészőhöz egyedileg
def generate_hwid(user_agent, screen_size, timezone):
    unique_string = f"{user_agent}_{screen_size}_{timezone}"
    hwid = hashlib.sha256(unique_string.encode()).hexdigest()
    return hwid


def initialize_activity_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_activity_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
                username VARCHAR(255) NULL,
                ip_address VARCHAR(45) NOT NULL,
                activity_type VARCHAR(50) NOT NULL,
                status VARCHAR(20) NOT NULL,
                details TEXT NULL,
                timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX (user_id),
                INDEX (ip_address),
                INDEX (timestamp)
            )
        """)
        conn.commit()
    except mysql.connector.Error as e:
        print(f"Error initializing activity logs table: {e}")
    finally:
        if cursor:
            cursor.close()

# Call this function during application initialization
initialize_activity_logs()


# Update the parse_ticket_messages function to handle system messages
def parse_ticket_messages(description):
    if not description:
        return []
    
    messages = []
    
    # First, check if this is just a single message with no replies
    if "--- User Reply (" not in description and "--- Admin Reply (" not in description and "--- System Message (" not in description:
        messages.append({"type": "initial", "text": description.strip()})
        return messages
    
    # Find the first delimiter position
    user_reply_pos = description.find("--- User Reply (")
    admin_reply_pos = description.find("--- Admin Reply (")
    system_msg_pos = description.find("--- System Message (")
    
    # Determine where the first reply starts
    first_delim_pos = -1
    positions = [p for p in [user_reply_pos, admin_reply_pos, system_msg_pos] if p >= 0]
    if positions:
        first_delim_pos = min(positions)
    
    if first_delim_pos > 0:
        # Extract the initial message (everything before the first delimiter)
        initial_message = description[:first_delim_pos].strip()
        messages.append({"type": "initial", "text": initial_message})
    else:
        # No replies found, just return the initial message
        messages.append({"type": "initial", "text": description.strip()})
        return messages
    
    # Process all replies
    current_pos = 0
    while current_pos < len(description):
        # Find the next delimiter
        user_reply_pos = description.find("--- User Reply (", current_pos)
        admin_reply_pos = description.find("--- Admin Reply (", current_pos)
        system_msg_pos = description.find("--- System Message (", current_pos)
        
        next_pos = -1
        reply_type = None
        prefix_len = 0
        
        # Determine which delimiter comes next
        positions = []
        if user_reply_pos >= current_pos:
            positions.append((user_reply_pos, "user_reply", len("--- User Reply (")))
        if admin_reply_pos >= current_pos:
            positions.append((admin_reply_pos, "admin_reply", len("--- Admin Reply (")))
        if system_msg_pos >= current_pos:
            positions.append((system_msg_pos, "system_message", len("--- System Message (")))
        
        if not positions:
            break
            
        # Sort by position and get the next one
        positions.sort()  # Sort by position (first element of tuple)
        next_pos, reply_type, prefix_len = positions[0]
            
        if next_pos < 0:
            break
            
        current_pos = next_pos
        
        # Extract timestamp
        timestamp_end = description.find(")", current_pos + prefix_len)
        if timestamp_end < 0:
            break
            
        timestamp_section = description[current_pos + prefix_len:timestamp_end]
        
        # For admin replies, extract admin name and role
        admin_name = None
        admin_role = None
        timestamp = timestamp_section
        
        if reply_type == "admin_reply" and " | " in timestamp_section:
            parts = timestamp_section.split(" | ")
            if len(parts) >= 3:
                timestamp = parts[0]
                admin_name = parts[1]
                admin_role = parts[2]
        
        # Find the start of the message content
        content_start = timestamp_end + 1
        while content_start < len(description) and description[content_start] in [' ', '\n', '\r', '-']:
            content_start += 1
        
        # Find the next delimiter or end
        next_user_pos = description.find("--- User Reply (", content_start)
        next_admin_pos = description.find("--- Admin Reply (", content_start)
        next_sys_pos = description.find("--- System Message (", content_start)
        
        next_delim_pos = -1
        positions = []
        if next_user_pos >= 0:
            positions.append(next_user_pos)
        if next_admin_pos >= 0:
            positions.append(next_admin_pos)
        if next_sys_pos >= 0:
            positions.append(next_sys_pos)
            
        if positions:
            next_delim_pos = min(positions)
        
        # Extract the message content
        if next_delim_pos >= 0:
            content = description[content_start:next_delim_pos].strip()
            current_pos = next_delim_pos
        else:
            content = description[content_start:].strip()
            current_pos = len(description)
        
        # Add message to the list
        message_data = {
            "type": reply_type,
            "text": content,
            "timestamp": timestamp
        }
        
        if reply_type == "admin_reply":
            message_data["admin_name"] = admin_name
            message_data["admin_role"] = admin_role
        
        messages.append(message_data)
    
    return messages
# Main route redirects to login or search based on session
@app.route('/')
def index():
    if 'user_id' in session and session.get('license_valid'):
        return redirect(url_for('search'))
    elif 'user_id' in session:
        # Changed: Check if a user is trying to access license management or profile
        requested_page = request.args.get('requested_page')
        if requested_page == 'profile':
            return redirect(url_for('profile'))  # Allow direct profile access
        return redirect(url_for('license'))
    else:
        return redirect(url_for('login'))

# REGISTRATION ROUTE
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        recaptcha_response = request.form.get('g-recaptcha-response')
        
        # Verify CAPTCHA first
        if not verify_recaptcha(recaptcha_response):
            log_user_activity(
                username=username,
                activity_type='registration',
                status='failed',
                details='CAPTCHA verification failed'
            )
            return render_template('register.html', error="CAPTCHA verification failed. Please try again.")
            
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Password validation
        if password != confirm_password:
            log_user_activity(
                username=username,
                activity_type='registration',
                status='failed',
                details="Passwords don't match"
            )
            return render_template('register.html', error="Passwords don't match")
        
        if len(password) < 8:
            log_user_activity(
                username=username,
                activity_type='registration',
                status='failed',
                details="Password too short (min 8 characters)"
            )
            return render_template('register.html', error="Password must be at least 8 characters long")
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            log_user_activity(
                username=username,
                activity_type='registration',
                status='failed',
                details="Username already exists"
            )
            return render_template('register.html', error="Username already exists")
        
        try:
            # Insert new user
            cursor.execute("INSERT INTO users (username, password, registration_date) VALUES (%s, %s, %s)", 
                          (username, hashed_password, datetime.now()))
            conn.commit()
            
            # Get the new user's ID
            user_id = cursor.lastrowid
            
            # Log successful registration
            log_user_activity(
                user_id=user_id,
                username=username,
                activity_type='registration',
                status='success',
                details="New account created"
            )
            
            # Set session data
            session['user_id'] = user_id
            session['username'] = username
            session['license_valid'] = False
            
            # After registration, redirect to license verification
            return redirect(url_for('license'))
            
        except mysql.connector.Error as e:
            log_user_activity(
                username=username,
                activity_type='registration',
                status='failed',
                details=f"Database error: {str(e)}"
            )
            error = "Registration failed: " + str(e)
            return render_template('register.html', error=error)
    
    return render_template('register.html')

# LOGIN ROUTE
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        recaptcha_response = request.form.get('g-recaptcha-response')
        username = request.form.get('username')
        
        # First, verify CAPTCHA
        if not verify_recaptcha(recaptcha_response):
            log_user_activity(
                username=username,
                activity_type='login',
                status='failed',
                details='CAPTCHA verification failed'
            )
            return render_template('login.html', error="CAPTCHA verification failed. Please try again.")
            
        password = request.form.get('password')
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # First check if user exists (without checking password yet)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if not user:
            # Close cursor and connection before logging activity
            cursor.close()
            conn.close()
            
            # User doesn't exist - log failed attempt
            log_user_activity(
                username=username,
                activity_type='login',
                status='failed',
                details='User not found'
            )
            # For security, keep the message generic
            return render_template('login.html', error="Invalid username or password")
        
        # Now check if password matches
        if user['password'] != hashed_password:
            # Store user_id for logging
            user_id = user['id']
            
            # Close cursor and connection before logging activity
            cursor.close()
            conn.close()
            
            # Password is wrong - log failed attempt
            log_user_activity(
                user_id=user_id,
                username=username,
                activity_type='login',
                status='failed',
                details='Invalid password'
            )
            return render_template('login.html', error="Invalid username or password")
        
        # Store user info before closing connection
        user_id = user['id']
        user_licensekey = user.get('licensekey')
        
        # Close cursor and connection before logging activity
        cursor.close()
        conn.close()
        
        # Login successful - log successful attempt
        log_user_activity(
            user_id=user_id,
            username=username,
            activity_type='login',
            status='success'
        )
        
        # Set session data
        session.permanent = True
        session['user_id'] = user_id
        session['username'] = username
        
        # Mark license as invalid by default, will be verified below
        session['license_valid'] = False
        
        # Check if user has a license key
        if user_licensekey:
            # Get browser info for HWID
            screen_size = request.form.get('screen_size', '1920x1080')
            timezone = request.form.get('timezone', 'UTC')
            user_agent = request.headers.get('User-Agent')
            hwid = generate_hwid(user_agent, screen_size, timezone)
            
            # Re-establish a new connection since previous one was closed
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            # Check if this license exists in the new integrated system
            cursor.execute("SELECT * FROM licenses WHERE licensekey = %s", (user_licensekey,))
            license_exists = cursor.fetchone()
            
            # Close this connection when done
            cursor.close()
            conn.close()
            
            # Only validate if the license exists in our new system
            if license_exists:
                # Verify the license is still valid
                is_valid, license_status = check_license(user_licensekey, hwid)
                
                if is_valid:
                    session['license_valid'] = True
                    log_user_activity(
                        user_id=user_id,
                        username=username,
                        activity_type='license_validation',
                        status='success',
                        details=f"License validated: {user_licensekey}"
                    )
                    return redirect(url_for('search'))
                else:
                    log_user_activity(
                        user_id=user_id,
                        username=username,
                        activity_type='license_validation',
                        status='failed',
                        details=f"License invalid: {license_status.get('message', 'Unknown error')}"
                    )
        
        # No valid license, redirect to license page
        return redirect(url_for('license'))
    
    return render_template('login.html')

# LOGOUT ROUTE
@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_user_activity(
            user_id=session['user_id'],
            username=session['username'],
            activity_type='logout',
            status='success'
        )
    session.clear()
    return redirect(url_for('login'))

# Add this after your existing functions
# Admin authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin login route
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check for admin credentials
        cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s AND is_admin = 1", 
                      (username, hashed_password))
        admin = cursor.fetchone()
        
        if admin:
            # Set session data for admin
            session['admin_logged_in'] = True
            session['admin_id'] = admin['id']
            session['admin_username'] = admin['username']
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin/admin_login.html', error="Invalid admin credentials")
    
    return render_template('admin/admin_login.html')
# Admin dashboard
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    recent_tickets = []
    
    try:
        # Get user count
        cursor.execute('SELECT COUNT(*) as count FROM users')
        result = cursor.fetchone()
        user_count = result['count'] if result else 0
        
        # Get number of admin users
        # Get open tickets count
        cursor.execute('SELECT COUNT(*) as count FROM support_tickets WHERE status = "open"')
        result = cursor.fetchone()
        open_tickets = result['count'] if result else 0
        
        # Get active licenses count
        cursor.execute('SELECT COUNT(*) as count FROM users WHERE licensekey IS NOT NULL')
        result = cursor.fetchone()
        active_licenses = result['count'] if result else 0
        
        # Get recent tickets
        cursor.execute('''
            SELECT t.id, t.issue_type, t.status, t.created_at, u.username 
            FROM support_tickets t
            JOIN users u ON t.user_id = u.id
            ORDER BY t.created_at DESC
            LIMIT 5
        ''')
        recent_tickets = cursor.fetchall()
        
        return render_template('admin/dashboard.html', 
                              user_count=user_count, 
                              open_tickets=open_tickets,
                              active_licenses=active_licenses,
                              recent_tickets=recent_tickets)
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'danger')
        return redirect(url_for('admin_login'))
    finally:
        if cursor:
            cursor.close()
# Add this route after the admin_ticket_detail route
# Admin delete ticket

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT id, username, registration_date, licensekey, is_admin 
            FROM users 
            ORDER BY registration_date DESC
        """)
        
        users = cursor.fetchall()
        
        return render_template('admin/users.html', users=users)
    except Exception as e:
        flash(f'Error loading users: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        close_db_connection(None, cursor)

# Add this route after your other user management routes
@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Check if user exists
        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
        
        username = user['username']
        
        # Check if this is an admin user
        cursor.execute("SELECT is_admin FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        
        # Don't allow deleting admin users for safety
        if user_data and user_data['is_admin'] == 1:
            return jsonify({'success': False, 'message': 'Cannot delete admin users for security reasons'})
            
        # Delete associated license HWIDs
        cursor.execute("""
            DELETE FROM license_hwids 
            WHERE license_id IN (SELECT id FROM licenses WHERE user_id = %s)
        """, (user_id,))
        
        # Set licenses to unassigned
        cursor.execute("UPDATE licenses SET user_id = NULL WHERE user_id = %s", (user_id,))
        
        # Delete support tickets
        cursor.execute("DELETE FROM support_tickets WHERE user_id = %s", (user_id,))
        
        # Finally delete the user
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        
        conn.commit()
        return jsonify({'success': True, 'message': f'User {username} deleted successfully'})
    except Exception as e:
        conn.rollback()
        print(f"Error deleting user: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})
    finally:
        if cursor:
            cursor.close()

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        if request.method == 'POST':
            username = request.form['username']
            is_admin = 1 if request.form.get('is_admin') else 0
            
            cursor.execute('UPDATE users SET username = %s, is_admin = %s WHERE id = %s',
                        (username, is_admin, user_id))
            conn.commit()
            
            flash('User updated successfully', 'success')
            return redirect(url_for('admin_users'))
        
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_users'))
            
        return render_template('admin/edit_user.html', user=user)
    except Exception as e:
        flash(f'Error editing user: {str(e)}', 'danger')
        return redirect(url_for('admin_users'))
    finally:
        if cursor:
            cursor.close()


@app.route('/users')
def users_directory():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Always verify license is still valid
    if not session.get('license_valid'):
        return redirect(url_for('license'))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    search_term = request.args.get('search', '')
    page = int(request.args.get('page', 1))
    per_page = 20
    offset = (page - 1) * per_page
    
    try:
        # Count total users for pagination
        if search_term:
            cursor.execute("SELECT COUNT(*) as count FROM users WHERE username LIKE %s", 
                         (f'%{search_term}%',))
        else:
            cursor.execute("SELECT COUNT(*) as count FROM users")
        
        total_users = cursor.fetchone()['count']
        total_pages = (total_users + per_page - 1) // per_page
        
        # Get users
        if search_term:
            cursor.execute("""
                SELECT u.id, u.username, u.registration_date, u.is_admin, 
                       (u.licensekey IS NOT NULL) as has_license,
                       l.active, l.expires_at
                FROM users u
                LEFT JOIN licenses l ON u.licensekey = l.licensekey
                WHERE u.username LIKE %s
                ORDER BY u.registration_date DESC
                LIMIT %s OFFSET %s
            """, (f'%{search_term}%', per_page, offset))
        else:
            cursor.execute("""
                SELECT u.id, u.username, u.registration_date, u.is_admin,
                       (u.licensekey IS NOT NULL) as has_license,
                       l.active, l.expires_at
                FROM users u
                LEFT JOIN licenses l ON u.licensekey = l.licensekey
                ORDER BY u.registration_date DESC
                LIMIT %s OFFSET %s
            """, (per_page, offset))
        
        users = cursor.fetchall()
        now = datetime.now()
        
        return render_template('users_directory.html', 
                          users=users, 
                          total_pages=total_pages, 
                          page=page, 
                          search_term=search_term,
                          now=now)
    except Exception as e:
        flash(f'Error loading users: {str(e)}', 'danger')
        return redirect(url_for('search'))
    finally:
        if cursor:
            cursor.close()

@app.route('/profile', methods=['GET', 'POST'])
@app.route('/profile/<username>', methods=['GET'])
def profile(username=None):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if not username and not session.get('license_valid'):
        flash('Note: Some features require an active license. Please activate a license to access all features.', 'info')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    error = None
    success = None
    is_own_profile = True
    is_admin = bool(session.get('admin_logged_in'))  # Check if current user is admin
    
    # If viewing someone else's profile, check license validity
    if username and username != session.get('username'):
        # Only allow if user has a valid license or is an admin
        if not session.get('license_valid') and not is_admin:
            flash('You need an active license to view other user profiles', 'danger')
            return redirect(url_for('license'))
            
        cursor.execute("""
            SELECT u.id, u.username, u.registration_date, u.is_admin, 
                   l.product, l.created_at, l.active, l.expires_at, l.hwid_limit, l.id as license_id,
                   l.licensekey
            FROM users u 
            LEFT JOIN licenses l ON u.licensekey = l.licensekey 
            WHERE u.username = %s
        """, (username,))
        user = cursor.fetchone()
        
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('search'))
            
        is_own_profile = False
        hwids = []
        
        # Only load HWIDs for admins viewing other profiles
        if is_admin and user.get('license_id'):
            cursor.execute("""
                SELECT * FROM license_hwids h
                WHERE h.license_id = %s
                ORDER BY h.last_used DESC
            """, (user['license_id'],))
            hwids = cursor.fetchall()
        
    else:
        # Viewing own profile - original logic
        cursor.execute("""
            SELECT u.*, l.* 
            FROM users u 
            LEFT JOIN licenses l ON u.licensekey = l.licensekey 
            WHERE u.id = %s
        """, (session['user_id'],))
        user = cursor.fetchone()
        
        # Get HWID information if license exists
        hwids = []
        if user and user.get('licensekey'):
            cursor.execute("""
                SELECT h.* FROM license_hwids h
                JOIN licenses l ON h.license_id = l.id
                WHERE l.licensekey = %s
            """, (user['licensekey'],))
            hwids = cursor.fetchall()
    
    if request.method == 'POST' and is_own_profile:
        # Process form submissions (only for own profile)
        action = request.form.get('action')
        
        # Handle password change
        if action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            # Verify current password
            current_hashed = hashlib.sha256(current_password.encode()).hexdigest()
            if current_hashed != user['password']:
                error = "Current password is incorrect"
                log_user_activity(
                    user_id=session['user_id'],
                    username=session['username'],
                    activity_type='password_change',
                    status='failed',
                    details=error
                )
            elif new_password != confirm_password:
                error = "New passwords don't match"
            elif len(new_password) < 8:
                error = "Password must be at least 8 characters long"
            else:
                log_user_activity(
                    user_id=session['user_id'],
                    username=session['username'],
                    activity_type='password_change',
                    status='success'
                )
                # Update password
                new_hashed = hashlib.sha256(new_password.encode()).hexdigest()
                cursor.execute("UPDATE users SET password = %s WHERE id = %s", (new_hashed, session['user_id']))
                conn.commit()
                success = "Password updated successfully"
        
        # Handle username change
        elif action == 'change_username':
            new_username = request.form.get('new_username')
            
            # Check if username exists
            cursor.execute("SELECT id FROM users WHERE username = %s AND id != %s", (new_username, session['user_id']))
            if cursor.fetchone():
                error = "Username already exists"
                log_user_activity(
                    user_id=session['user_id'],
                    username=session['username'],
                    activity_type='username_change',
                    status='failed',
                    details=error
                )
            else:
                log_user_activity(
                    user_id=session['user_id'],
                    username=new_username,  # Log the new username
                    activity_type='username_change',
                    status='success',
                    details=f"Changed from {session['username']} to {new_username}"
                )
                cursor.execute("UPDATE users SET username = %s WHERE id = %s", (new_username, session['user_id']))
                conn.commit()
                session['username'] = new_username
                success = "Username updated successfully"
        
        # Handle HWID reset
        elif action == 'reset_hwid':
            if user and user.get('id') and user.get('hwid_limit', 0) > 0:
                cursor.execute("DELETE FROM license_hwids WHERE license_id = %s", (user['id'],))
                conn.commit()
                success = "Hardware ID reset successful. You can now use your license on new devices."
            else:
                error = "No active license found or HWID reset not allowed"
    
    # Get activity logs - for both own profile AND admin viewing someone else's profile
    activity_logs = []
    if is_own_profile:
        # User viewing their own profile
        cursor.execute("""
            SELECT * FROM user_activity_logs
            WHERE user_id = %s
            ORDER BY timestamp DESC
            LIMIT 10
        """, (session['user_id'],))
        activity_logs = cursor.fetchall()
    elif is_admin and user:  # Admin viewing another user's profile
        cursor.execute("""
            SELECT * FROM user_activity_logs
            WHERE user_id = %s OR (username = %s AND user_id IS NULL)
            ORDER BY timestamp DESC
            LIMIT 25
        """, (user['id'], user['username']))
        activity_logs = cursor.fetchall()
    
    return render_template('profile.html', 
                           user=user, 
                           hwids=hwids,
                           error=error,
                           success=success,
                           now=datetime.now(),
                           is_own_profile=is_own_profile,
                           is_admin=is_admin,
                           activity_logs=activity_logs)

@app.route('/admin/users/view/<int:user_id>')
@admin_required
def admin_view_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get user details with license information
        cursor.execute('''
            SELECT u.*, 
                   u.registration_date as created_at, -- alias for consistent naming
                   l.id as license_id, l.licensekey, l.product, l.active, 
                   l.created_at as license_created_at, l.expires_at, 
                   l.days_valid, l.hwid_limit, l.last_used
            FROM users u 
            LEFT JOIN licenses l ON u.licensekey = l.licensekey
            WHERE u.id = %s
        ''', (user_id,))
        
        user = cursor.fetchone()
        
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_users'))
        
        # Ensure all dates are properly initialized to prevent template errors
        if 'created_at' not in user or user['created_at'] is None:
            user['created_at'] = datetime.now()
        
        if 'registration_date' not in user or user['registration_date'] is None:
            user['registration_date'] = user['created_at']
        
        # Get user's tickets
        cursor.execute('''
            SELECT * FROM support_tickets
            WHERE user_id = %s
            ORDER BY created_at DESC
        ''', (user_id,))
        
        tickets = cursor.fetchall()
        
        # Get HWID information if license exists
        hwids = []
        if user and user.get('license_id'):
            cursor.execute("""
                SELECT * FROM license_hwids 
                WHERE license_id = %s
                ORDER BY last_used DESC
            """, (user['license_id'],))
            hwids = cursor.fetchall()
        
        # Always get activity logs regardless of license status
        cursor.execute("""
            SELECT * FROM user_activity_logs
            WHERE user_id = %s OR (username = %s AND user_id IS NULL)
            ORDER BY timestamp DESC
            LIMIT 25
        """, (user_id, user['username']))
        activity_logs = cursor.fetchall()
        
        # IMPORTANT: This return statement must be outside any conditionals
        return render_template('admin/view_user.html',
                          user=user, 
                          hwids=hwids,
                          tickets=tickets,
                          now=datetime.now(),
                          activity_logs=activity_logs)
                          
    except Exception as e:
        flash(f'Error viewing user: {str(e)}', 'danger')
        return redirect(url_for('admin_users'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

#
# user management
#

# Add these routes to support the enhanced admin user view



@app.route('/admin/reset-password/<int:user_id>', methods=['POST'])
@admin_required
def admin_reset_password(user_id):
    if request.method == 'POST':
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        try:
            new_password = request.form.get('new_password')
            require_reset = request.form.get('require_reset') == 'on'
            
            if not new_password or len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
                return redirect(url_for('admin_view_user', user_id=user_id))
            
            # Check if user exists
            cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            
            if not user:
                flash('User not found', 'danger')
                return redirect(url_for('admin_users'))
            
            # Hash the new password
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            
            # Update the user's password
            cursor.execute(
                "UPDATE users SET password = %s, password_reset_required = %s WHERE id = %s", 
                (hashed_password, require_reset, user_id)
            )
            conn.commit()
            
            flash(f'Password for {user["username"]} has been reset successfully', 'success')
            return redirect(url_for('admin_view_user', user_id=user_id))
            
        except Exception as e:
            flash(f'Error resetting password: {str(e)}', 'danger')
            return redirect(url_for('admin_view_user', user_id=user_id))
        finally:
            if cursor:
                cursor.close()

@app.route('/admin/assign-license/<int:user_id>', methods=['POST'])
@admin_required
def admin_assign_license(user_id):
    if request.method == 'POST':
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Check if user exists
            cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            
            if not user:
                flash('User not found', 'danger')
                return redirect(url_for('admin_users'))
                
            license_method = request.form.get('license_method')
            
            if license_method == 'existing':
                licensekey = request.form.get('licensekey')
                if not licensekey:
                    flash('License key is required', 'danger')
                    return redirect(url_for('admin_view_user', user_id=user_id))
                    
                # Check if license exists and is available
                cursor.execute("""
                    SELECT id, user_id, active 
                    FROM licenses 
                    WHERE licensekey = %s
                """, (licensekey,))
                license_data = cursor.fetchone()
                
                if not license_data:
                    flash('License key not found', 'danger')
                    return redirect(url_for('admin_view_user', user_id=user_id))
                    
                if not license_data['active']:
                    flash('License key is inactive', 'danger')
                    return redirect(url_for('admin_view_user', user_id=user_id))
                    
                if license_data['user_id'] and license_data['user_id'] != user_id:
                    flash('License key is already assigned to another user', 'danger')
                    return redirect(url_for('admin_view_user', user_id=user_id))
                
                # First, remove any existing license assignment
                cursor.execute("UPDATE users SET licensekey = NULL WHERE id = %s", (user_id,))
                
                # Then assign the new license
                cursor.execute("UPDATE users SET licensekey = %s WHERE id = %s", (licensekey, user_id))
                cursor.execute("UPDATE licenses SET user_id = %s WHERE licensekey = %s", (user_id, licensekey))
                conn.commit()
                
                flash(f'License key {licensekey} assigned to {user["username"]} successfully', 'success')
                
            else:  # generate new license
                license_type = request.form.get('license_type')
                hwid_limit = int(request.form.get('hwid_limit', 2))
                
                days_valid = 0
                expires_at = None
                
                if license_type == 'temporary':
                    days_valid = int(request.form.get('days_valid', 30))
                    expires_at = datetime.now() + timedelta(days=days_valid)
                
                # Generate a new license key
                license_key = generate_license_key()
                
                # Insert the new license
                cursor.execute(
                    """INSERT INTO licenses 
                       (licensekey, product, user_id, active, created_at, expires_at, days_valid, hwid_limit, created_by) 
                       VALUES (%s, %s, %s, %s, NOW(), %s, %s, %s, %s)""",
                    (license_key, 'steamdatabase', user_id, True, expires_at, days_valid, hwid_limit, session.get('admin_username'))
                )
                
                # Update the user record
                cursor.execute("UPDATE users SET licensekey = %s WHERE id = %s", (license_key, user_id))
                conn.commit()
                
                flash(f'New license {license_key} generated and assigned to {user["username"]} successfully', 'success')
            
            return redirect(url_for('admin_view_user', user_id=user_id))
            
        except Exception as e:
            conn.rollback()
            flash(f'Error assigning license: {str(e)}', 'danger')
            return redirect(url_for('admin_view_user', user_id=user_id))
        finally:
            if cursor:
                cursor.close()

@app.route('/admin/reset-user-hwid/<int:user_id>', methods=['POST'])
@admin_required
def admin_reset_user_hwid(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Check if user exists and has a license
        cursor.execute("""
            SELECT u.id, u.username, u.licensekey, l.id as license_id 
            FROM users u
            LEFT JOIN licenses l ON u.licensekey = l.licensekey
            WHERE u.id = %s
        """, (user_id,))
        
        user_data = cursor.fetchone()
        
        if not user_data or not user_data.get('licensekey'):
            flash('User not found or has no license assigned', 'danger')
            return redirect(url_for('admin_view_user', user_id=user_id))
        
        license_id = user_data.get('license_id')
        if not license_id:
            flash('License record not found in the database', 'danger')
            return redirect(url_for('admin_view_user', user_id=user_id))
        
        # Delete all HWID records for this license
        cursor.execute("DELETE FROM license_hwids WHERE license_id = %s", (license_id,))
        conn.commit()
        
        flash(f'Hardware IDs for user {user_data["username"]} have been reset successfully', 'success')
        return redirect(url_for('admin_view_user', user_id=user_id))
        
    except Exception as e:
        conn.rollback()
        flash(f'Error resetting hardware IDs: {str(e)}', 'danger')
        return redirect(url_for('admin_view_user', user_id=user_id))
    finally:
        if cursor:
            cursor.close()

@app.route('/admin/revoke-user-license/<int:user_id>', methods=['POST'])
@admin_required
def admin_revoke_user_license(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Check if user exists and has a license
        cursor.execute("""
            SELECT u.id, u.username, u.licensekey, l.id as license_id 
            FROM users u
            LEFT JOIN licenses l ON u.licensekey = l.licensekey
            WHERE u.id = %s
        """, (user_id,))
        
        user_data = cursor.fetchone()
        
        if not user_data or not user_data.get('licensekey'):
            flash('User not found or has no license assigned', 'danger')
            return redirect(url_for('admin_view_user', user_id=user_id))
        
        license_id = user_data.get('license_id')
        license_key = user_data.get('licensekey')
        
        # Get option to deactivate the license key
        deactivate_license = request.form.get('deactivate_license') == 'on'
        
        # Remove license from user
        cursor.execute("UPDATE users SET licensekey = NULL WHERE id = %s", (user_id,))
        
        # If requested, deactivate the license
        if deactivate_license and license_id:
            cursor.execute("UPDATE licenses SET active = FALSE, user_id = NULL WHERE id = %s", (license_id,))
            # Also remove any HWIDs associated with this license
            cursor.execute("DELETE FROM license_hwids WHERE license_id = %s", (license_id,))
            flash_message = f'License key {license_key} has been revoked and deactivated'
        else:
            # Just unlink the license from the user
            cursor.execute("UPDATE licenses SET user_id = NULL WHERE id = %s", (license_id,))
            flash_message = f'License key {license_key} has been unlinked from user {user_data["username"]}'
        
        conn.commit()
        flash(flash_message, 'success')
        return redirect(url_for('admin_view_user', user_id=user_id))
        
    except Exception as e:
        conn.rollback()
        flash(f'Error revoking license: {str(e)}', 'danger')
        return redirect(url_for('admin_view_user', user_id=user_id))
    finally:
        if cursor:
            cursor.close()

# Add route to get user's hardware IDs for AJAX calls
@app.route('/admin/get-user-hwids/<int:user_id>')
@admin_required
def admin_get_user_hwids(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get the user's license
        cursor.execute("""
            SELECT u.licensekey, l.id as license_id 
            FROM users u
            LEFT JOIN licenses l ON u.licensekey = l.licensekey
            WHERE u.id = %s
        """, (user_id,))
        
        user_license = cursor.fetchone()
        
        if not user_license or not user_license.get('license_id'):
            return jsonify({'success': False, 'message': 'No license found for this user'})
        
        # Get hardware IDs for this license
        cursor.execute("""
            SELECT h.id, h.hwid, h.first_used, h.last_used 
            FROM license_hwids h
            WHERE h.license_id = %s
            ORDER BY h.last_used DESC
        """, (user_license['license_id'],))
        
        hwids = cursor.fetchall()
        
        # Format the dates for JSON
        formatted_hwids = []
        for hwid in hwids:
            formatted_hwids.append({
                'id': hwid['id'],
                'hwid': hwid['hwid'],
                'first_used': hwid['first_used'].strftime('%Y-%m-%d %H:%M:%S') if hwid['first_used'] else None,
                'last_used': hwid['last_used'].strftime('%Y-%m-%d %H:%M:%S') if hwid['last_used'] else None
            })
        
        return jsonify({
            'success': True, 
            'hwids': formatted_hwids,
            'license_id': user_license['license_id'],
            'license_key': user_license['licensekey']
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        if cursor:
            cursor.close()

# Add route to fetch all license-related data for a user (for admin view)
@app.route('/admin/user-license-data/<int:user_id>')
@admin_required
def admin_user_license_data(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get the user and license details
        cursor.execute("""
            SELECT u.*, l.* 
            FROM users u 
            LEFT JOIN licenses l ON u.licensekey = l.licensekey 
            WHERE u.id = %s
        """, (user_id,))
        
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
        
        # Get HWID information
        hwids = []
        if user.get('id') and user.get('licensekey'):
            cursor.execute("""
                SELECT h.* FROM license_hwids h
                JOIN licenses l ON h.license_id = l.id
                WHERE l.licensekey = %s
            """, (user['licensekey'],))
            
            hw_records = cursor.fetchall()
            
            for record in hw_records:
                hwids.append({
                    'id': record['id'],
                    'hwid': record['hwid'],
                    'first_used': record['first_used'].strftime('%Y-%m-%d %H:%M:%S') if record['first_used'] else None,
                    'last_used': record['last_used'].strftime('%Y-%m-%d %H:%M:%S') if record['last_used'] else None
                })
        
        # Sanitize user object for JSON response (format dates, etc.)
        sanitized_user = {}
        for key, value in user.items():
            if isinstance(value, datetime):
                sanitized_user[key] = value.strftime('%Y-%m-%d %H:%M:%S')
            else:
                sanitized_user[key] = value
        
        return jsonify({
            'success': True,
            'user': sanitized_user,
            'hwids': hwids,
            'now': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        if cursor:
            cursor.close()

# Create license_hwids table if not exists
def initialize_hwid_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Create license_hwids table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS license_hwids (
                id INT AUTO_INCREMENT PRIMARY KEY,
                license_id INT NOT NULL,
                hwid VARCHAR(255) NOT NULL,
                first_used DATETIME NOT NULL,
                last_used DATETIME NOT NULL,
                FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE
            )
        """)
        conn.commit()
    except mysql.connector.Error as e:
        print(f"Error initializing HWID table: {e}")
    finally:
        if cursor:
            cursor.close()

# Add this call to the initialization section
initialize_hwid_table()


@app.route('/admin/delete-ticket/<int:ticket_id>')
@admin_required
def admin_delete_ticket(ticket_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM support_tickets WHERE id = %s", (ticket_id,))
        conn.commit()
        flash('Ticket deleted successfully', 'success')
    except mysql.connector.Error as e:
        flash(f'Error deleting ticket: {str(e)}', 'error')
    finally:
        close_db_connection(None, cursor)
    
    return redirect(url_for('admin_support_tickets'))

# Define status constants
TICKET_STATUS = {
    'open': 'primary',
    'in_progress': 'warning',
    'closed': 'success'
}

@app.route('/admin/support_tickets')
@admin_required
def admin_support_tickets():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''
            SELECT t.*, u.username 
            FROM support_tickets t 
            JOIN users u ON t.user_id = u.id 
            ORDER BY 
                CASE 
                    WHEN t.status = 'open' THEN 1 
                    WHEN t.status = 'in_progress' THEN 2 
                    ELSE 3 
                END, 
                t.created_at DESC
        ''')
        tickets = cursor.fetchall()
        return render_template('admin/support_tickets.html', tickets=tickets, status_classes=TICKET_STATUS)
    except mysql.connector.Error as e:
        flash(f'Error loading tickets: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        if cursor:
            cursor.close()

# View individual support ticket
@app.route('/admin/support-tickets/<int:ticket_id>', methods=['GET', 'POST'])
@admin_required
def admin_ticket_detail(ticket_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Define status classes for badges
    status_classes = {
        'open': 'danger',
        'in_progress': 'warning',
        'closed': 'success'
    }
    
    if request.method == 'POST':
        admin_reply = request.form.get('admin_reply')
        status = request.form.get('status')
        
        # First get the current status to check if it's changing
        cursor.execute("SELECT status FROM support_tickets WHERE id = %s", (ticket_id,))
        current_ticket = cursor.fetchone()
        current_status = current_ticket['status'] if current_ticket else None
        
        status_changed = current_status and status and current_status != status
        
        # Format status change message if needed
        status_message = ""
        if status_changed:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
            status_message = f"\n\n--- System Message ({timestamp}) ---\nTicket status changed from '{current_status}' to '{status}'."
        
        if admin_reply and admin_reply.strip():
            # Get admin username
            admin_username = session.get('admin_username', 'Admin')
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
            
            # Format reply
            admin_reply_formatted = f"\n\n--- Admin Reply ({timestamp} | {admin_username} | Administrator) ---\n{admin_reply.strip()}"
            
            # Combine with status change if needed
            message_to_add = admin_reply_formatted + status_message if status_changed else admin_reply_formatted
            
            # Update ticket with new reply
            cursor.execute("""
                UPDATE support_tickets 
                SET description = CONCAT(description, %s),
                    status = %s,
                    updated_at = %s
                WHERE id = %s
            """, (message_to_add, status, datetime.now(), ticket_id))
            
            conn.commit()
            flash('Reply sent successfully', 'success')
        elif status_changed:
            # Only status changed, add just the system message
            cursor.execute("""
                UPDATE support_tickets 
                SET description = CONCAT(description, %s),
                    status = %s,
                    updated_at = %s
                WHERE id = %s
            """, (status_message, status, datetime.now(), ticket_id))
            
            conn.commit()
            flash('Ticket status updated', 'success')
        elif status:
            # Just update status without adding a message
            cursor.execute("""
                UPDATE support_tickets 
                SET status = %s,
                    updated_at = %s
                WHERE id = %s
            """, (status, datetime.now(), ticket_id))
            
            conn.commit()
            flash('Ticket status updated', 'success')
        
        # Redirect to prevent form resubmission
        return redirect(url_for('admin_ticket_detail', ticket_id=ticket_id))
    
    # Get the ticket with user information
    cursor.execute("""
        SELECT t.*, u.username, u.licensekey, u.id as user_id
        FROM support_tickets t
        JOIN users u ON t.user_id = u.id
        WHERE t.id = %s
    """, (ticket_id,))
    
    ticket = cursor.fetchone()
    
    if not ticket:
        flash('Ticket not found', 'error')
        return redirect(url_for('admin_support_tickets'))
    
    # Parse messages from ticket description
    messages = parse_ticket_messages(ticket['description'])
    
    return render_template('admin/ticket_detail.html', 
                          ticket=ticket, 
                          messages=messages, 
                          status_classes=status_classes)# User's tickets route (add this if not already present)
TICKET_STATUS = {
    'open': 'danger',
    'in_progress': 'warning',
    'closed': 'success'
}

# Then update your my_tickets route
@app.route('/my-tickets')
def my_tickets():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''
            SELECT * FROM support_tickets 
            WHERE user_id = %s 
            ORDER BY created_at DESC
        ''', (session['user_id'],))
        
        tickets = cursor.fetchall()
        
        # Pass the status_classes dictionary to the template
        return render_template('my_tickets.html', tickets=tickets, status_classes=TICKET_STATUS)
    except Exception as e:
        flash(f"Error loading tickets: {str(e)}", "danger")
        return redirect(url_for('dashboard'))
    finally:
        if cursor:
            cursor.close()

# Admin logout
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    return redirect(url_for('admin_login'))
# LICENCE ROUTE 

# Consolidate the redundant ticket routes
@app.route('/ticket/<int:ticket_id>')
def view_ticket(ticket_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # First, check if the ticket belongs to the current user
        cursor.execute("""
            SELECT t.*, u.username 
            FROM support_tickets t
            JOIN users u ON t.user_id = u.id
            WHERE t.id = %s AND t.user_id = %s
        """, (ticket_id, session['user_id']))
        
        ticket = cursor.fetchone()
        
        if not ticket:
            flash("Ticket not found or you don't have permission to view it", "error")
            return redirect(url_for('my_tickets'))
        
        # Debug: Print the description
        print(f"DEBUG - Original description: {ticket['description']}")
        
        # Initialize messages as an empty list by default
        messages = []
        
        # Only parse the description if it exists
        if ticket['description']:
            messages = parse_ticket_messages(ticket['description'])
            # Debug: Print the parsed messages
            print(f"DEBUG - Parsed messages: {messages}")
        else:
            # Fallback for tickets with empty description
            messages = [{"type": "initial", "text": "No initial description provided.", "timestamp": None}]
        
        return render_template('view_ticket.html', ticket=ticket, messages=messages, status_classes=TICKET_STATUS)
    except Exception as e:
        flash(f"Error viewing ticket: {str(e)}", "error")
        print(f"ERROR - Exception in view_ticket: {str(e)}")
        return redirect(url_for('my_tickets'))
    finally:
        if cursor:
            cursor.close()


@app.route('/license', methods=['GET', 'POST'])
def license():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        licensekey = request.form.get('licensekey')
        screen_size = request.form.get('screen_size')
        timezone = request.form.get('timezone')
        user_agent = request.headers.get('User-Agent')
        hwid = generate_hwid(user_agent, screen_size, timezone)
        
        is_valid, status = check_license(licensekey, hwid)
        
        if is_valid:
            session['license_valid'] = True
            # Update user's license key in the users table
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET licensekey=%s WHERE id=%s", (licensekey, session['user_id']))
            conn.commit()
            log_user_activity(
                user_id=session['user_id'],
                username=session['username'],
                activity_type='license_activation',
                status='success',
                details=f"Activated license: {licensekey}"
            )
            return redirect(url_for('search'))
        else:
            error_msg = f"Invalid license key. Error: {status.get('message', 'Unknown error')}"
            return render_template('license.html', error=error_msg)
    
    # Check if user already has a license key
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT licensekey FROM users WHERE id=%s", (session['user_id'],))
    user = cursor.fetchone()
    
    return render_template('license.html', saved_license=user['licensekey'] if user and user['licensekey'] else None)

# User reply to a ticket
@app.route('/my-tickets/<int:ticket_id>/reply', methods=['POST'])
def reply_ticket(ticket_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get the user's reply from the form
    user_reply = request.form.get('user_reply')
    
    if not user_reply or not user_reply.strip():
        flash("Reply cannot be empty", "error")
        return redirect(url_for('view_ticket', ticket_id=ticket_id))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # First, check if the ticket belongs to the user
        cursor.execute("SELECT * FROM support_tickets WHERE id = %s AND user_id = %s",
                      (ticket_id, session['user_id']))
        
        ticket = cursor.fetchone()
        
        if not ticket:
            flash("Ticket not found or you don't have permission to reply", "error")
            return redirect(url_for('my_tickets'))
        
        # Format the reply with timestamp in the expected format
        now = datetime.now()
        timestamp = now.strftime('%Y-%m-%d %H:%M')
        
        # This is the key change - format it exactly as expected by the parser
        # Note the double-dash format that matches what the parser looks for
        formatted_reply = f"\n\n--- User Reply ({timestamp}) \n{user_reply.strip()}"
        
        # Append to existing description
        current_description = ticket['description'] or ""
        updated_description = current_description + formatted_reply
        
        # Update the ticket status to open if it was closed
        new_status = 'open' if ticket['status'] == 'closed' else ticket['status']
        
        # Update the ticket
        try:
            cursor.execute("""
                UPDATE support_tickets 
                SET description = %s, status = %s, updated_at = %s
                WHERE id = %s
            """, (updated_description, new_status, now, ticket_id))
            conn.commit()
        except mysql.connector.Error:
            # If updated_at column doesn't exist
            cursor.execute("""
                UPDATE support_tickets 
                SET description = %s, status = %s
                WHERE id = %s
            """, (updated_description, new_status, ticket_id))
            conn.commit()
        
        flash("Reply submitted successfully", "success")
        
    except mysql.connector.Error as e:
        flash(f"Error submitting reply: {str(e)}", "error")
    finally:
        if cursor:
            cursor.close()
    
    return redirect(url_for('view_ticket', ticket_id=ticket_id))
# SUPPORT ROUTE
@app.route('/support', methods=['GET', 'POST'])
def support():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        issue = request.form.get('issue')
        description = request.form.get('description')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("INSERT INTO support_tickets (user_id, issue_type, description, created_at, status) VALUES (%s, %s, %s, %s, %s)",
                          (session['user_id'], issue, description, datetime.now(), 'open'))
            conn.commit()
            return render_template('support.html', success="Your support request has been submitted. We'll contact you soon.")
        except mysql.connector.Error as e:
            return render_template('support.html', error=f"Error submitting support request: {str(e)}")
    
    return render_template('support.html')



#
# Internal License system
#

# Replace the existing check_license function with our internal implementation
def check_license(licensekey, hwid):
    """
    Internal license validation system that ensures one license per user
    Returns (is_valid, status_dict)
    """
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Check if license exists and is active
        cursor.execute("""
            SELECT l.*, u.username, u.id as assigned_user_id
            FROM licenses l
            LEFT JOIN users u ON l.user_id = u.id
            WHERE l.licensekey = %s
        """, (licensekey,))
        
        license_data = cursor.fetchone()
        
        if not license_data:
            return False, {
                "status_code": 404,
                "message": "License key not found in our database"
            }
            
        if not license_data['active']:
            return False, {
                "status_code": 403,
                "message": "This license key has been deactivated"
            }
            
        # Check if license is expired
        if license_data.get('expires_at') and license_data['expires_at'] < datetime.now():
            # Set license to inactive
            cursor.execute("UPDATE licenses SET active = FALSE WHERE id = %s", 
                          (license_data['id'],))
            conn.commit()
            
            # Calculate how long ago it expired
            days_expired = (datetime.now() - license_data['expires_at']).days
            
            return False, {
                "status_code": 403,
                "message": f"License expired {days_expired} days ago on {license_data['expires_at'].strftime('%Y-%m-%d')}"
            }
            
        # Check if license is already assigned to a different user
        current_user_id = session.get('user_id')
        
        # If the license has days_valid but no expiration date set and is being assigned to a user,
        # set the expiration date now (this is the key change)
        if license_data.get('days_valid', 0) > 0 and not license_data.get('expires_at') and current_user_id:
            # Set expiration date to now + days_valid
            expires_at = datetime.now() + timedelta(days=license_data['days_valid'])
            cursor.execute("UPDATE licenses SET expires_at = %s WHERE id = %s", 
                           (expires_at, license_data['id']))
            conn.commit()
            # Update the license_data to reflect this change
            license_data['expires_at'] = expires_at
            
        if license_data['assigned_user_id'] is not None and license_data['assigned_user_id'] != current_user_id:
            return False, {
                "status_code": 403,
                "message": f"This license is already assigned to user '{license_data['username']}'"
            }
            
        # Rest of the function remains the same...
        # (HWID checking, assigning license to current user, updating last_used time, etc.)
        
        # Check HWID binding
        cursor.execute("SELECT * FROM license_hwids WHERE license_id = %s", (license_data['id'],))
        hwids = cursor.fetchall()
        hwid_limit = license_data.get('hwid_limit', 2)
        
        # Check if this HWID is already registered with this license
        hwid_registered = False
        for h in hwids:
            if h['hwid'] == hwid:
                hwid_registered = True
                # Update last used time
                cursor.execute("""
                    UPDATE license_hwids 
                    SET last_used = NOW()
                    WHERE id = %s
                """, (h['id'],))
                conn.commit()
                break
                
        if not hwid_registered:
            # Check if we've reached the HWID limit
            if len(hwids) >= hwid_limit:
                return False, {
                    "status_code": 403,
                    "message": f"HWID limit reached ({hwid_limit}). Please reset your HWID or contact support."
                }
            
            # Register new HWID
            cursor.execute("""
                INSERT INTO license_hwids 
                (license_id, hwid, first_used, last_used)
                VALUES (%s, %s, NOW(), NOW())
            """, (license_data['id'], hwid))
            conn.commit()
        
        # If current user doesn't own this license yet, remove any previous license and assign this one
        if current_user_id and license_data['user_id'] != current_user_id:
            # Clear any previous license assigned to this user
            cursor.execute("""
                UPDATE licenses 
                SET user_id = NULL 
                WHERE user_id = %s
            """, (current_user_id,))
            
            # Update users table to clear previous license
            cursor.execute("""
                UPDATE users 
                SET licensekey = NULL 
                WHERE id = %s
            """, (current_user_id,))
            
            # Assign this license to the current user
            cursor.execute("""
                UPDATE licenses 
                SET user_id = %s 
                WHERE id = %s
            """, (current_user_id, license_data['id']))
            
            # Update users table with the new license
            cursor.execute("""
                UPDATE users 
                SET licensekey = %s 
                WHERE id = %s
            """, (licensekey, current_user_id))
            conn.commit()
        
        # Update license last used time
        cursor.execute("UPDATE licenses SET last_used = NOW() WHERE id = %s", 
                      (license_data['id'],))
        conn.commit()
        
        # Prepare license info for display
        license_type = "Permanent" if not license_data.get('expires_at') else "Temporary"
        expires_info = ""
        if license_data.get('expires_at'):
            days_left = (license_data['expires_at'] - datetime.now()).days
            expires_info = f", {days_left} days remaining"
        
        return True, {
            "status_code": 200,
            "message": f"License validated successfully ({license_type}{expires_info})",
            "username": license_data.get('username', "Unknown"),
            "product": license_data.get('product', 'steamdatabase'),
            "expires_at": license_data.get('expires_at'),
            "hwid_limit": hwid_limit,
            "hwids_used": len(hwids),
            "license_type": license_type
        }
        
    except Exception as e:
        print(f"License check error: {str(e)}")
        return False, {
            "status_code": 500,
            "message": f"Server error during license validation: {str(e)}"
        }
    finally:
        if cursor:
            cursor.close()

# Initialize license database tables if they don't exist
def initialize_license_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Create licenses table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                id INT AUTO_INCREMENT PRIMARY KEY,
                licensekey VARCHAR(255) NOT NULL UNIQUE,
                product VARCHAR(255) NOT NULL DEFAULT 'steamdatabase',
                user_id INT,
                active BOOLEAN DEFAULT TRUE,
                created_at DATETIME NOT NULL,
                expires_at DATETIME NULL,
                days_valid INT DEFAULT 0,
                last_used DATETIME NULL,
                hwid_limit INT DEFAULT 2,
                notes TEXT NULL,
                created_by VARCHAR(255) NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        
        # Add days_valid column if it doesn't exist
        try:
            cursor.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS days_valid INT DEFAULT 0")
        except mysql.connector.Error:
            # MySQL version may not support IF NOT EXISTS with ALTER TABLE
            try:
                cursor.execute("SHOW COLUMNS FROM licenses LIKE 'days_valid'")
                if not cursor.fetchone():
                    cursor.execute("ALTER TABLE licenses ADD COLUMN days_valid INT DEFAULT 0")
            except:
                pass
                
        conn.commit()
    except mysql.connector.Error as e:
        print(f"Error initializing license database: {e}")
    finally:
        if cursor:
            cursor.close()

# Generate a license key
def generate_license_key():
    characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    sections = 4
    section_length = 4
    
    license_parts = []
    for _ in range(sections):
        section = ''.join(random.choice(characters) for _ in range(section_length))
        license_parts.append(section)
    
    return '-'.join(license_parts)

# Add this to your init section right after db = get_db_connection()
initialize_license_database()

# Add admin license management routes
@app.route('/admin/licenses')
@admin_required
def admin_licenses():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    now = datetime.now()
    try:
        # Get all licenses
        cursor.execute('''
            SELECT l.*, u.username 
            FROM licenses l
            LEFT JOIN users u ON l.user_id = u.id
            ORDER BY l.created_at DESC
            LIMIT 100
        ''')
        licenses = cursor.fetchall()
        
        # Count active licenses
        cursor.execute("SELECT COUNT(*) AS count FROM licenses WHERE active = 1")
        active_result = cursor.fetchone()
        active_licenses = active_result['count'] if active_result else 0
        
        # Count expired licenses
        cursor.execute("SELECT COUNT(*) AS count FROM licenses WHERE active = 0")
        expired_result = cursor.fetchone()
        expired_licenses = expired_result['count'] if expired_result else 0
        
        return render_template('admin/licenses.html',
                            licenses=licenses, 
                            active_licenses=active_licenses,
                            expired_licenses=expired_licenses,
                            now=now)
    except Exception as e:
        flash(f'Error loading licenses: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        if cursor:
            cursor.close()

# Create a new license
@app.route('/admin/licenses/create', methods=['POST'])
@admin_required
def admin_create_license():
    if request.method == 'POST':
        product = request.form.get('product', 'steamdatabase')
        username = request.form.get('username')
        gen_type = request.form.get('gen_type', 'auto')
        manual_key = request.form.get('manual_key')
        license_type = request.form.get('license_type', 'permanent')
        days_valid = int(request.form.get('days_valid', 0))
        hwid_limit = int(request.form.get('hwid_limit', 2))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            user_id = None
            if username:
                # Find the user by username
                cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
                user_result = cursor.fetchone()
                if user_result:
                    user_id = user_result[0]
                    
                    # Check if user already has a license
                    cursor.execute("SELECT licensekey FROM users WHERE id = %s AND licensekey IS NOT NULL", (user_id,))
                    existing_license = cursor.fetchone()
                    if existing_license:
                        flash(f'User {username} already has license key {existing_license[0]}. Please remove that license first.', 'warning')
                        return redirect(url_for('admin_licenses'))
            
            # Generate or use provided license key
            if gen_type == 'manual' and manual_key:
                # Format the manual key if needed
                license_key = manual_key.strip().upper()
                
                # Check if this key already exists
                cursor.execute("SELECT id FROM licenses WHERE licensekey = %s", (license_key,))
                if cursor.fetchone():
                    flash(f'License key {license_key} already exists', 'danger')
                    return redirect(url_for('admin_licenses'))
            else:
                # Generate a license key
                license_key = generate_license_key()
            
            # Store the days_valid but don't set expires_at yet
            expires_at = None
            days_to_store = days_valid if license_type == 'temporary' else 0
                
            # Check if license is already assigned to another user
            cursor.execute("SELECT user_id FROM licenses WHERE licensekey = %s", (license_key,))
            existing_user = cursor.fetchone()
            if existing_user and existing_user[0] and existing_user[0] != user_id:
                flash(f'License key {license_key} is already assigned to another user', 'danger')
                return redirect(url_for('admin_licenses'))
            
            # Save to the database (now including days_valid)
            cursor.execute(
                """INSERT INTO licenses 
                   (licensekey, product, user_id, active, created_at, expires_at, days_valid, hwid_limit, created_by) 
                   VALUES (%s, %s, %s, %s, NOW(), %s, %s, %s, %s)""",
                (license_key, product, user_id, True, expires_at, days_to_store, hwid_limit, session.get('admin_username'))
            )
            conn.commit()
            
            # If a username is specified and the user exists, assign the license to them 
            # and start the expiration countdown if it's a temporary license
            if user_id and days_to_store > 0:
                # Set expiration date to now + days_valid
                expires_at = datetime.now() + timedelta(days=days_to_store)
                cursor.execute("UPDATE licenses SET expires_at = %s WHERE licensekey = %s", (expires_at, license_key))
                cursor.execute("UPDATE users SET licensekey = %s WHERE id = %s", (license_key, user_id))
                conn.commit()
            elif user_id:
                cursor.execute("UPDATE users SET licensekey = %s WHERE id = %s", (license_key, user_id))
                conn.commit()
            
            flash(f'License key {license_key} created successfully', 'success')
            return redirect(url_for('admin_licenses'))
        except Exception as e:
            conn.rollback()
            flash(f'Error creating license: {str(e)}', 'danger')
            return redirect(url_for('admin_licenses'))
        finally:
            if cursor:
                cursor.close()

# Reset HWID for a license
@app.route('/admin/licenses/reset-hwid/<int:license_id>', methods=['POST'])
@admin_required
def admin_reset_hwid(license_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # First validate the license exists
        cursor.execute("SELECT licensekey FROM licenses WHERE id = %s", (license_id,))
        license_result = cursor.fetchone()
        
        if not license_result:
            return jsonify({'success': False, 'message': 'License not found'})
        
        # Delete all HWIDs for this license
        cursor.execute("DELETE FROM license_hwids WHERE license_id = %s", (license_id,))
        conn.commit()
        
        return jsonify({'success': True, 'message': 'HWID reset successful'})
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)})
    finally:
        if cursor:
            cursor.close()

# Delete a license
@app.route('/admin/licenses/delete/<int:license_id>', methods=['POST'])
@admin_required
def admin_delete_license(license_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get the license key before deleting
        cursor.execute("SELECT licensekey FROM licenses WHERE id = %s", (license_id,))
        license_result = cursor.fetchone()
        
        if not license_result:
            return jsonify({'success': False, 'message': 'License not found'})
        
        license_key = license_result[0]
        
        # Remove license from any users
        cursor.execute("UPDATE users SET licensekey = NULL WHERE licensekey = %s", (license_key,))
        
        # Delete from license_hwids (should cascade but just in case)
        cursor.execute("DELETE FROM license_hwids WHERE license_id = %s", (license_id,))
        
        # Delete the license
        cursor.execute("DELETE FROM licenses WHERE id = %s", (license_id,))
        conn.commit()
        
        return jsonify({'success': True, 'message': 'License deleted successfully'})
    except Exception as e:
        conn.rollback()
        print(f"Error deleting license: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})
    finally:
        if cursor:
            cursor.close()

# Bulk create licenses
@app.route('/admin/licenses/bulk', methods=['POST'])
@admin_required
def admin_bulk_licenses():
    if request.method == 'POST':
        product = request.form.get('product', 'steamdatabase')
        count = int(request.form.get('count', 10))
        license_type = request.form.get('license_type', 'permanent')
        days_valid = int(request.form.get('days_valid', 0))
        hwid_limit = int(request.form.get('hwid_limit', 2))
        
        if count < 1 or count > 100:
            flash('Invalid number of licenses to generate (1-100 allowed)', 'danger')
            return redirect(url_for('admin_licenses'))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            generated_keys = []
            
            # Store days_valid but don't set expires_at yet (it will be set when assigned)
            days_to_store = days_valid if license_type == 'temporary' else 0
            expires_at = None  # Not setting expiration until used
                
            for _ in range(count):
                license_key = generate_license_key()
                generated_keys.append(license_key)
                
                # Save to database (now including days_valid)
                cursor.execute(
                    """INSERT INTO licenses 
                       (licensekey, product, active, created_at, expires_at, days_valid, hwid_limit, created_by) 
                       VALUES (%s, %s, %s, NOW(), %s, %s, %s, %s)""",
                    (license_key, product, True, expires_at, days_to_store, hwid_limit, session.get('admin_username'))
                )
            
            conn.commit()
            
            # Create a CSV file for download
            csv_content = "License Key,Product,Type,Days Valid\n"
            license_type_str = "Temporary" if license_type == 'temporary' else "Permanent"
            days_str = str(days_valid) if license_type == 'temporary' else "N/A"
            
            for key in generated_keys:
                csv_content += f"{key},{product},{license_type_str},{days_str}\n"
                
            # Create a response with the CSV
            response = make_response(csv_content)
            response.headers['Content-Disposition'] = f'attachment; filename=licenses_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            response.headers['Content-Type'] = 'text/csv'
            
            flash(f'Successfully generated {count} license keys', 'success')
            return response
        except Exception as e:
            conn.rollback()
            flash(f'Error generating licenses: {str(e)}', 'danger')
            return redirect(url_for('admin_licenses'))
        finally:
            if cursor:
                cursor.close()

# Clear expired licenses
@app.route('/admin/licenses/clear-expired', methods=['POST'])
@admin_required
def admin_clear_expired_licenses():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # First count how many expired licenses we have
        cursor.execute("SELECT COUNT(*) AS count FROM licenses WHERE active = 0")
        result = cursor.fetchone()
        count = result[0] if result else 0
        
        if count == 0:
            flash('No expired licenses to clear', 'info')
            return redirect(url_for('admin_licenses'))
        
        # Get list of expired licenses to remove from users
        cursor.execute("SELECT licensekey FROM licenses WHERE active = 0")
        expired_licenses = [row[0] for row in cursor.fetchall()]
        
        # Remove licenses from users
        placeholders = ','.join(['%s'] * len(expired_licenses))
        cursor.execute(f"UPDATE users SET licensekey = NULL WHERE licensekey IN ({placeholders})", expired_licenses)
        
        # Delete from license_hwids
        cursor.execute("DELETE FROM license_hwids WHERE license_id IN (SELECT id FROM licenses WHERE active = 0)")
        
        # Delete expired licenses
        cursor.execute("DELETE FROM licenses WHERE active = 0")
        conn.commit()
        
        flash(f'Successfully cleared {count} expired licenses', 'success')
        return redirect(url_for('admin_licenses'))
    except Exception as e:
        conn.rollback()
        flash(f'Error clearing expired licenses: {str(e)}', 'danger')
        return redirect(url_for('admin_licenses'))
    finally:
        if cursor:
            cursor.close()

# View license details
@app.route('/admin/licenses/view/<int:license_id>')
@admin_required
def admin_view_license(license_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''
            SELECT l.*, u.username 
            FROM licenses l
            LEFT JOIN users u ON l.user_id = u.id
            WHERE l.id = %s
        ''', (license_id,))
        license = cursor.fetchone()
        
        if not license:
            return jsonify({'success': False, 'message': 'License not found'})
        
        # Format dates for display
        if license['created_at']:
            license['created_at'] = license['created_at'].strftime('%Y-%m-%d %H:%M')
        if license['last_used']:
            license['last_used'] = license['last_used'].strftime('%Y-%m-%d %H:%M')
        if license['expires_at']:
            license['expires_at'] = license['expires_at'].strftime('%Y-%m-%d %H:%M')
        
        # Get HWIDs associated with this license
        cursor.execute("SELECT hwid, first_used, last_used FROM license_hwids WHERE license_id = %s", (license_id,))
        hwids = cursor.fetchall()
        
        # Format hwid data for the frontend
        formatted_hwids = []
        for hwid_data in hwids:
            formatted_hwids.append({
                'hwid': hwid_data['hwid'],
                'first_used': hwid_data['first_used'].strftime('%Y-%m-%d %H:%M'),
                'last_used': hwid_data['last_used'].strftime('%Y-%m-%d %H:%M')
            })
        
        license['hwids'] = formatted_hwids
        license['hwid_cap'] = license.get('hwid_limit', 2)
        
        return jsonify({'success': True, 'license': license})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        if cursor:
            cursor.close()


# Add this route after your other license routes:

# Search for licenses
@app.route('/admin/licenses/search')
@admin_required
def admin_search_license():
    search_term = request.args.get('q', '')
    search_type = request.args.get('type', 'key')
    
    if not search_term:
        flash('Please enter a search term', 'warning')
        return redirect(url_for('admin_licenses'))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        query = ""
        
        if search_type == 'key':
            query = """
                SELECT l.*, u.username 
                FROM licenses l
                LEFT JOIN users u ON l.user_id = u.id
                WHERE l.licensekey LIKE %s
                ORDER BY l.created_at DESC
            """
            search_param = f"%{search_term}%"
        elif search_type == 'username':
            query = """
                SELECT l.*, u.username 
                FROM licenses l
                LEFT JOIN users u ON l.user_id = u.id
                WHERE u.username LIKE %s
                ORDER BY l.created_at DESC
            """
            search_param = f"%{search_term}%"
        elif search_type == 'product':
            query = """
                SELECT l.*, u.username 
                FROM licenses l
                LEFT JOIN users u ON l.user_id = u.id
                WHERE l.product LIKE %s
                ORDER BY l.created_at DESC
            """
            search_param = f"%{search_term}%"
        else:
            # Default to key search
            query = """
                SELECT l.*, u.username 
                FROM licenses l
                LEFT JOIN users u ON l.user_id = u.id
                WHERE l.licensekey LIKE %s
                ORDER BY l.created_at DESC
            """
            search_param = f"%{search_term}%"
        
        cursor.execute(query, (search_param,))
        licenses = cursor.fetchall()
        
        # Count active licenses (for sidebar)
        cursor.execute("SELECT COUNT(*) AS count FROM licenses WHERE active = 1")
        active_result = cursor.fetchone()
        active_licenses = active_result['count'] if active_result else 0
        
        # Count expired licenses (for sidebar)
        cursor.execute("SELECT COUNT(*) AS count FROM licenses WHERE active = 0")
        expired_result = cursor.fetchone()
        expired_licenses = expired_result['count'] if expired_result else 0
        
        return render_template('admin/licenses.html', 
                            licenses=licenses,
                            active_licenses=active_licenses,
                            expired_licenses=expired_licenses,
                            is_search=True,
                            search_term=search_term)
    except Exception as e:
        flash(f'Error searching licenses: {str(e)}', 'danger')
        return redirect(url_for('admin_licenses'))
    finally:
        if cursor:
            cursor.close()


@app.route('/admin/generate-license-for-ticket/<int:ticket_id>', methods=['POST'])
@admin_required
def admin_generate_license_for_ticket(ticket_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get the ticket with user information
        cursor.execute("""
            SELECT t.*, u.username, u.licensekey as existing_license
            FROM support_tickets t
            JOIN users u ON t.user_id = u.id
            WHERE t.id = %s
        """, (ticket_id,))
        
        ticket = cursor.fetchone()
        
        if not ticket:
            flash('Ticket not found', 'danger')
            return redirect(url_for('admin_support_tickets'))
        
        user_id = ticket['user_id']
        username = ticket['username']
        
        # Check if user already has a license
        if ticket['existing_license']:
            # Get the old license ID
            cursor.execute("SELECT id FROM licenses WHERE licensekey = %s", (ticket['existing_license'],))
            old_license = cursor.fetchone()
            
            if old_license:
                # Deactivate the old license
                cursor.execute("""
                    UPDATE licenses 
                    SET active = FALSE, user_id = NULL 
                    WHERE id = %s
                """, (old_license['id'],))
                
                # Also remove any HWIDs associated with this license
                cursor.execute("DELETE FROM license_hwids WHERE license_id = %s", (old_license['id'],))
        
        # Generate a new license key
        license_key = generate_license_key()
        
        # Create a new license in the database
        cursor.execute(
            """INSERT INTO licenses 
               (licensekey, product, user_id, active, created_at, hwid_limit, created_by) 
               VALUES (%s, %s, %s, %s, NOW(), %s, %s)""",
            (license_key, 'steamdatabase', user_id, True, 2, session.get('admin_username'))
        )
        
        # Update the user record with the new license
        cursor.execute("UPDATE users SET licensekey = %s WHERE id = %s", (license_key, user_id))
        
        # Add a system message to the ticket about the new license
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
        system_message = f"\n\n--- System Message ({timestamp}) ---\nA new license key '{license_key}' has been generated for this account."
        
        # Append the system message to the ticket description
        cursor.execute("""
            UPDATE support_tickets
            SET description = CONCAT(description, %s)
            WHERE id = %s
        """, (system_message, ticket_id))
        
        # Add admin notes as before
        admin_notes = ticket.get('admin_notes', '') or ''
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if admin_notes:
            admin_notes += f"\n\n[{timestamp}] Generated new license: {license_key}"
        else:
            admin_notes = f"[{timestamp}] Generated new license: {license_key}"
            
        cursor.execute("UPDATE support_tickets SET admin_notes = %s WHERE id = %s", 
                      (admin_notes, ticket_id))
        
        conn.commit()
        flash(f'Successfully generated new license key for {username}', 'success')
        
        return redirect(url_for('admin_ticket_detail', ticket_id=ticket_id))
        
    except Exception as e:
        conn.rollback()
        flash(f'Error generating license: {str(e)}', 'danger')
        return redirect(url_for('admin_ticket_detail', ticket_id=ticket_id))
    finally:
        if cursor:
            cursor.close()






# SEARCH ROUTE
@app.route('/search', methods=['GET', 'POST'])
def search():
    # Check if user is logged in 
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Always verify license is still valid on each page access
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get the user's current license key
    cursor.execute("SELECT licensekey FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    
    license_valid = False
    if user and user['licensekey']:
        # Check if license exists in the new system
        cursor.execute("SELECT * FROM licenses WHERE licensekey = %s", (user['licensekey'],))
        license_exists = cursor.fetchone()
        
        if license_exists:
            # Generate HWID to verify
            user_agent = request.headers.get('User-Agent')
            screen_size = request.cookies.get('screen_size', '1920x1080')
            timezone = request.cookies.get('timezone', 'UTC')
            hwid = generate_hwid(user_agent, screen_size, timezone)
            
            # Verify license validity
            is_valid, _ = check_license(user['licensekey'], hwid)
            license_valid = is_valid
    
    # Update session and redirect if license is no longer valid
    session['license_valid'] = license_valid
    if not license_valid:
        return redirect(url_for('license'))

    db = get_db_connection()
    cursor = db.cursor()

    # Fiókok számának lekérdezése
    cursor.execute("SELECT COUNT(*) FROM captured_data")
    account_count = cursor.fetchone()[0]

    # Játékok lekérdezése
    cursor.execute("SELECT games FROM captured_data")
    games_raw = cursor.fetchall()

    game_set = set()
    for game_tuple in games_raw:
        if game_tuple[0]:  # Ensure not None
            game_list = game_tuple[0].split(' | ')
            game_set.update(game_list)

    sorted_games = sorted(game_set)

    # Országok lekérdezése
    cursor.execute("SELECT DISTINCT country FROM captured_data")
    countries = [row[0] for row in cursor.fetchall() if row[0]]  # Filter out None values

    # Összes Steam balance összegzése
    cursor.execute("SELECT SUM(balance) FROM captured_data")
    total_balance = cursor.fetchone()[0] or 0

    filtered_data = []

    if request.method == 'POST':
        # Szűrési feltételek lekérése
        selected_games = request.form.getlist('games')
        selected_countries = request.form.getlist('countries')
        min_balance = request.form.get('min_balance')
        max_balance = request.form.get('max_balance')

        # Szűrt adatok lekérdezése
        query = "SELECT * FROM captured_data WHERE 1=1"
        if selected_games:
            query += " AND (" + " OR ".join(f"games LIKE %s" for _ in selected_games) + ")"
        if selected_countries:
            query += " AND country IN (" + ",".join(["%s"] * len(selected_countries)) + ")"
        if min_balance and min_balance.strip():
            query += " AND balance >= %s"
        if max_balance and max_balance.strip():
            query += " AND balance <= %s"
        
        # Build parameters list
        params = []
        if selected_games:
            params.extend([f"%{game}%" for game in selected_games])
        if selected_countries:
            params.extend(selected_countries)
        if min_balance and min_balance.strip():
            params.append(float(min_balance))
        if max_balance and max_balance.strip():
            params.append(float(max_balance))
        
        cursor.execute(query, params)
        filtered_data = cursor.fetchall()

    return render_template(
        'index.html',
        games=sorted_games,
        countries=countries,
        filtered_data=filtered_data,
        account_count=account_count,
        total_balance=total_balance,
        username=session.get('username')
    )

if __name__ == '__main__':
    app.run(debug=True)