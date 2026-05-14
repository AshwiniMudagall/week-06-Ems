"""
app.py - FieldOps Manager
Week 6 Features (builds on Week 5):
  - Razorpay Payment Gateway (test mode) — Client → Admin flow
  - Admin → Electrician payment disbursement
  - Transaction history with full audit trail
  - Job amount & client info fields
  - Payment success / failure handling
  - Security hardening (HMAC signature verification)
"""

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database import init_db, get_db
from functools import wraps
from datetime import date
import os
import hmac
import hashlib

# ── Try importing razorpay; fall back to demo mode if not installed ───────────
try:
    import razorpay
    RAZORPAY_AVAILABLE = True
except ImportError:
    RAZORPAY_AVAILABLE = False

# ─── APP CONFIG ───────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fieldops_secret_week6_secure')

# Razorpay keys — set these as environment variables on Render/Railway
# Get free test keys from: https://dashboard.razorpay.com/  (free signup)
RAZORPAY_KEY_ID     = os.environ.get('RAZORPAY_KEY_ID',     'rzp_test_REPLACE_ME')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET', 'REPLACE_WITH_SECRET')

# File upload config
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
init_db()

# ─── HELPERS ──────────────────────────────────────────────────────────────────
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_notifications():
    db = get_db()
    notes = []
    pending_tasks = db.execute("SELECT COUNT(*) FROM tasks WHERE status='Pending'").fetchone()[0]
    if pending_tasks:
        notes.append({'type': 'info', 'msg': f'{pending_tasks} task(s) are Pending'})
    done = db.execute("SELECT COUNT(*) FROM tasks WHERE status='Completed'").fetchone()[0]
    if done:
        notes.append({'type': 'success', 'msg': f'{done} task(s) completed'})
    today = date.today().isoformat()
    overdue = db.execute(
        "SELECT COUNT(*) FROM jobs WHERE deadline <= ? AND status != 'Completed'", (today,)
    ).fetchone()[0]
    if overdue:
        notes.append({'type': 'danger', 'msg': f'{overdue} job(s) have passed deadline!'})
    # Week 6: notify about unpaid jobs
    unpaid = db.execute(
        "SELECT COUNT(*) FROM jobs WHERE payment_status='Unpaid' AND amount > 0"
    ).fetchone()[0]
    if unpaid:
        notes.append({'type': 'warning', 'msg': f'{unpaid} job(s) awaiting client payment'})
    db.close()
    return notes


# ─── ACCESS CONTROL ───────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        if session.get('user_role') != 'admin':
            flash('Access denied. Admins only.', 'danger')
            return redirect(url_for('electrician_tasks'))
        return f(*args, **kwargs)
    return decorated


# ─── AUTH ─────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not email or not password:
            flash('Both email and password are required.', 'danger')
            return render_template('login.html')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        db.close()
        if user and check_password_hash(user['password'], password):
            session['user_id']   = user['id']
            session['user_name'] = user['name']
            session['user_role'] = user['role']
            return redirect(url_for('dashboard') if user['role'] == 'admin' else url_for('electrician_tasks'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name     = request.form.get('name', '').strip()
        phone    = request.form.get('phone', '').strip()
        email    = request.form.get('email', '').strip().lower()
        role     = request.form.get('role', 'electrician')
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')
        if not name or not email or not password:
            flash('Name, email, and password are required.', 'danger')
            return render_template('register.html')
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('register.html')
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
        hashed = generate_password_hash(password)
        db = get_db()
        try:
            db.execute('INSERT INTO users (name,phone,email,role,password) VALUES (?,?,?,?,?)',
                       (name, phone, email, role, hashed))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception:
            flash('Email already exists.', 'danger')
        finally:
            db.close()
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


# ─── ELECTRICIAN VIEW ─────────────────────────────────────────────────────────
@app.route('/my-tasks')
@login_required
def electrician_tasks():
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    electrician = db.execute('SELECT * FROM electricians WHERE email=?', (user['email'],)).fetchone()
    tasks = []
    if electrician:
        tasks = db.execute('''
            SELECT tasks.*, jobs.title AS job_title
            FROM tasks LEFT JOIN jobs ON tasks.job_id = jobs.id
            WHERE tasks.electrician_id = ?
            ORDER BY tasks.id DESC
        ''', (electrician['id'],)).fetchall()
    db.close()
    return render_template('electrician_tasks.html', tasks=tasks, electrician=electrician)


@app.route('/my-tasks/update/<int:tid>', methods=['POST'])
@login_required
def electrician_update_task(tid):
    status = request.form.get('status', '')
    if status not in ['Pending', 'In Progress', 'Completed']:
        flash('Invalid status.', 'danger')
        return redirect(url_for('electrician_tasks'))
    db = get_db()
    db.execute('UPDATE tasks SET status=? WHERE id=?', (status, tid))
    db.execute("INSERT INTO activity (message) VALUES (?)",
               (f"Task #{tid} updated to '{status}' by {session.get('user_name', 'electrician')}",))
    db.commit()
    db.close()
    flash(f"Task updated to '{status}'.", 'success')
    return redirect(url_for('electrician_tasks'))


# ─── ADMIN DASHBOARD ──────────────────────────────────────────────────────────
@app.route('/dashboard')
@admin_required
def dashboard():
    db = get_db()
    elec  = db.execute('SELECT COUNT(*) FROM electricians').fetchone()[0]
    jobs  = db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0]
    tasks = db.execute('SELECT COUNT(*) FROM tasks').fetchone()[0]
    done  = db.execute("SELECT COUNT(*) FROM tasks WHERE status='Completed'").fetchone()[0]
    mats  = db.execute('SELECT COUNT(*) FROM materials').fetchone()[0]
    recent = db.execute('SELECT * FROM activity ORDER BY id DESC LIMIT 5').fetchall()
    pending_tasks  = db.execute("SELECT COUNT(*) FROM tasks WHERE status='Pending'").fetchone()[0]
    inprog_tasks   = db.execute("SELECT COUNT(*) FROM tasks WHERE status='In Progress'").fetchone()[0]
    jobs_pending   = db.execute("SELECT COUNT(*) FROM jobs WHERE status='Pending'").fetchone()[0]
    jobs_inprog    = db.execute("SELECT COUNT(*) FROM jobs WHERE status='In Progress'").fetchone()[0]
    jobs_done      = db.execute("SELECT COUNT(*) FROM jobs WHERE status='Completed'").fetchone()[0]
    # Week 6: revenue summary
    total_collected = db.execute(
        "SELECT COALESCE(SUM(amount),0) FROM payments WHERE payment_type='client_to_admin' AND status='success'"
    ).fetchone()[0]
    total_disbursed = db.execute(
        "SELECT COALESCE(SUM(amount),0) FROM payments WHERE payment_type='admin_to_electrician' AND status='success'"
    ).fetchone()[0]
    db.close()
    notifications = get_notifications()
    return render_template('dashboard.html',
        electricians=elec, jobs=jobs, tasks=tasks,
        completed=done, materials=mats, recent=recent,
        notifications=notifications,
        pending_tasks=pending_tasks, inprog_tasks=inprog_tasks,
        jobs_pending=jobs_pending, jobs_inprog=jobs_inprog, jobs_done=jobs_done,
        total_collected=total_collected, total_disbursed=total_disbursed
    )


# ─── ELECTRICIANS ─────────────────────────────────────────────────────────────
@app.route('/electricians')
@admin_required
def electricians():
    db = get_db()
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', 'All')
    query = 'SELECT * FROM electricians WHERE 1=1'
    params = []
    if search:
        query += ' AND (name LIKE ? OR phone LIKE ? OR specialization LIKE ?)'
        params += [f'%{search}%', f'%{search}%', f'%{search}%']
    if status_filter != 'All':
        query += ' AND status=?'
        params.append(status_filter)
    data = db.execute(query, params).fetchall()
    db.close()
    return render_template('electricians.html', electricians=data,
                           search=search, status_filter=status_filter)


@app.route('/electricians/add', methods=['POST'])
@admin_required
def add_electrician():
    name           = request.form.get('name', '').strip()
    phone          = request.form.get('phone', '').strip()
    email          = request.form.get('email', '').strip()
    specialization = request.form.get('specialization', '').strip()
    if not name:
        flash('Name is required.', 'danger')
        return redirect(url_for('electricians'))
    db = get_db()
    db.execute('INSERT INTO electricians (name,phone,email,specialization) VALUES (?,?,?,?)',
               (name, phone, email, specialization))
    db.execute("INSERT INTO activity (message) VALUES (?)", (f"Electrician '{name}' added",))
    db.commit()
    db.close()
    flash(f"Electrician '{name}' added.", 'success')
    return redirect(url_for('electricians'))


@app.route('/electricians/edit/<int:eid>', methods=['GET', 'POST'])
@admin_required
def edit_electrician(eid):
    db = get_db()
    if request.method == 'POST':
        name           = request.form.get('name', '').strip()
        phone          = request.form.get('phone', '').strip()
        email          = request.form.get('email', '').strip()
        specialization = request.form.get('specialization', '').strip()
        status         = request.form.get('status', 'Active')
        if not name:
            flash('Name is required.', 'danger')
            db.close()
            return redirect(url_for('edit_electrician', eid=eid))
        db.execute('''UPDATE electricians SET name=?,phone=?,email=?,specialization=?,status=?
                      WHERE id=?''', (name, phone, email, specialization, status, eid))
        db.execute("INSERT INTO activity (message) VALUES (?)", (f"Electrician '{name}' updated",))
        db.commit()
        db.close()
        flash(f"Electrician '{name}' updated.", 'success')
        return redirect(url_for('electricians'))
    electrician = db.execute('SELECT * FROM electricians WHERE id=?', (eid,)).fetchone()
    db.close()
    if not electrician:
        flash('Not found.', 'danger')
        return redirect(url_for('electricians'))
    return render_template('edit_electrician.html', electrician=electrician)


@app.route('/electricians/delete/<int:eid>')
@admin_required
def delete_electrician(eid):
    db = get_db()
    row = db.execute('SELECT name FROM electricians WHERE id=?', (eid,)).fetchone()
    if row:
        db.execute('DELETE FROM electricians WHERE id=?', (eid,))
        db.execute("INSERT INTO activity (message) VALUES (?)", (f"Electrician '{row['name']}' deleted",))
        db.commit()
        flash(f"Electrician '{row['name']}' deleted.", 'success')
    else:
        flash('Not found.', 'danger')
    db.close()
    return redirect(url_for('electricians'))


# ─── JOBS ─────────────────────────────────────────────────────────────────────
@app.route('/jobs')
@admin_required
def jobs():
    db = get_db()
    search        = request.args.get('search', '').strip()
    status_filter = request.args.get('status', 'All')
    query = '''SELECT jobs.*, electricians.name AS electrician_name
               FROM jobs LEFT JOIN electricians ON jobs.electrician_id = electricians.id
               WHERE 1=1'''
    params = []
    if search:
        query += ' AND (jobs.title LIKE ? OR jobs.location LIKE ?)'
        params += [f'%{search}%', f'%{search}%']
    if status_filter != 'All':
        query += ' AND jobs.status=?'
        params.append(status_filter)
    data = db.execute(query, params).fetchall()
    electricians_list = db.execute('SELECT * FROM electricians').fetchall()
    db.close()
    return render_template('jobs.html', jobs=data, electricians=electricians_list,
                           search=search, status_filter=status_filter)


@app.route('/jobs/add', methods=['POST'])
@admin_required
def add_job():
    title          = request.form.get('title', '').strip()
    location       = request.form.get('location', '').strip()
    deadline       = request.form.get('deadline', '')
    electrician_id = request.form.get('electrician_id') or None
    client_name    = request.form.get('client_name', '').strip()
    client_email   = request.form.get('client_email', '').strip()
    try:
        amount = float(request.form.get('amount', 0) or 0)
    except ValueError:
        amount = 0.0
    if not title:
        flash('Job title is required.', 'danger')
        return redirect(url_for('jobs'))
    image_filename = None
    if 'job_image' in request.files:
        file = request.files['job_image']
        if file and file.filename and allowed_file(file.filename):
            image_filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
    db = get_db()
    db.execute('''INSERT INTO jobs (title,location,deadline,electrician_id,image_filename,
                                   amount,client_name,client_email)
                  VALUES (?,?,?,?,?,?,?,?)''',
               (title, location, deadline, electrician_id, image_filename,
                amount, client_name, client_email))
    db.execute("INSERT INTO activity (message) VALUES (?)", (f"Job '{title}' created",))
    db.commit()
    db.close()
    flash(f"Job '{title}' created.", 'success')
    return redirect(url_for('jobs'))


@app.route('/jobs/edit/<int:jid>', methods=['GET', 'POST'])
@admin_required
def edit_job(jid):
    db = get_db()
    if request.method == 'POST':
        title          = request.form.get('title', '').strip()
        location       = request.form.get('location', '').strip()
        deadline       = request.form.get('deadline', '')
        electrician_id = request.form.get('electrician_id') or None
        status         = request.form.get('status', 'Pending')
        client_name    = request.form.get('client_name', '').strip()
        client_email   = request.form.get('client_email', '').strip()
        try:
            amount = float(request.form.get('amount', 0) or 0)
        except ValueError:
            amount = 0.0
        if not title:
            flash('Job title is required.', 'danger')
            db.close()
            return redirect(url_for('edit_job', jid=jid))
        db.execute('''UPDATE jobs SET title=?,location=?,deadline=?,electrician_id=?,status=?,
                                     amount=?,client_name=?,client_email=?
                      WHERE id=?''',
                   (title, location, deadline, electrician_id, status,
                    amount, client_name, client_email, jid))
        db.execute("INSERT INTO activity (message) VALUES (?)", (f"Job '{title}' updated",))
        db.commit()
        db.close()
        flash(f"Job '{title}' updated.", 'success')
        return redirect(url_for('jobs'))
    job = db.execute('SELECT * FROM jobs WHERE id=?', (jid,)).fetchone()
    electricians_list = db.execute('SELECT * FROM electricians').fetchall()
    db.close()
    if not job:
        flash('Job not found.', 'danger')
        return redirect(url_for('jobs'))
    return render_template('edit_job.html', job=job, electricians=electricians_list)


@app.route('/jobs/delete/<int:jid>')
@admin_required
def delete_job(jid):
    db = get_db()
    row = db.execute('SELECT title FROM jobs WHERE id=?', (jid,)).fetchone()
    if row:
        db.execute('DELETE FROM jobs WHERE id=?', (jid,))
        db.execute("INSERT INTO activity (message) VALUES (?)", (f"Job '{row['title']}' deleted",))
        db.commit()
        flash(f"Job '{row['title']}' deleted.", 'success')
    else:
        flash('Job not found.', 'danger')
    db.close()
    return redirect(url_for('jobs'))


@app.route('/jobs/status/<int:jid>', methods=['POST'])
@admin_required
def update_job_status(jid):
    status = request.form.get('status', '')
    if status not in ['Pending', 'In Progress', 'Completed']:
        flash('Invalid status.', 'danger')
        return redirect(url_for('jobs'))
    db = get_db()
    row = db.execute('SELECT title FROM jobs WHERE id=?', (jid,)).fetchone()
    if row:
        db.execute('UPDATE jobs SET status=? WHERE id=?', (status, jid))
        db.execute("INSERT INTO activity (message) VALUES (?)",
                   (f"Job '{row['title']}' status → '{status}'",))
        db.commit()
        flash(f"Job status updated to '{status}'.", 'success')
    else:
        flash('Job not found.', 'danger')
    db.close()
    return redirect(url_for('jobs'))


# ─── TASKS ────────────────────────────────────────────────────────────────────
@app.route('/tasks')
@admin_required
def tasks():
    db = get_db()
    status_filter = request.args.get('status', 'All')
    search = request.args.get('search', '').strip()
    query = '''SELECT tasks.*, jobs.title AS job_title, electricians.name AS electrician_name
               FROM tasks
               LEFT JOIN jobs ON tasks.job_id = jobs.id
               LEFT JOIN electricians ON tasks.electrician_id = electricians.id
               WHERE 1=1'''
    params = []
    if status_filter != 'All':
        query += ' AND tasks.status=?'
        params.append(status_filter)
    if search:
        query += ' AND tasks.task LIKE ?'
        params.append(f'%{search}%')
    data = db.execute(query, params).fetchall()
    jobs_list = db.execute('SELECT * FROM jobs').fetchall()
    electricians_list = db.execute('SELECT * FROM electricians').fetchall()
    db.close()
    return render_template('tasks.html', tasks=data,
                           jobs=jobs_list, electricians=electricians_list,
                           status_filter=status_filter, search=search)


@app.route('/tasks/add', methods=['POST'])
@admin_required
def add_task():
    task           = request.form.get('task', '').strip()
    job_id         = request.form.get('job_id') or None
    electrician_id = request.form.get('electrician_id') or None
    status         = request.form.get('status', 'Pending')
    if not task:
        flash('Task description is required.', 'danger')
        return redirect(url_for('tasks'))
    db = get_db()
    db.execute('INSERT INTO tasks (task,job_id,electrician_id,status) VALUES (?,?,?,?)',
               (task, job_id, electrician_id, status))
    db.execute("INSERT INTO activity (message) VALUES (?)", (f"Task '{task[:30]}' assigned",))
    db.commit()
    db.close()
    flash('Task assigned.', 'success')
    return redirect(url_for('tasks'))


@app.route('/tasks/update_status/<int:tid>', methods=['POST'])
@admin_required
def update_task_status(tid):
    status = request.form.get('status', '')
    if status not in ['Pending', 'In Progress', 'Completed']:
        flash('Invalid status.', 'danger')
        return redirect(url_for('tasks'))
    db = get_db()
    db.execute('UPDATE tasks SET status=? WHERE id=?', (status, tid))
    db.execute("INSERT INTO activity (message) VALUES (?)", (f"Task #{tid} → '{status}'",))
    db.commit()
    db.close()
    flash(f'Task #{tid} updated.', 'success')
    return redirect(url_for('tasks'))


@app.route('/tasks/delete/<int:tid>')
@admin_required
def delete_task(tid):
    db = get_db()
    db.execute('DELETE FROM tasks WHERE id=?', (tid,))
    db.commit()
    db.close()
    flash(f'Task #{tid} deleted.', 'success')
    return redirect(url_for('tasks'))


# ─── MATERIALS ────────────────────────────────────────────────────────────────
@app.route('/materials')
@admin_required
def materials():
    db = get_db()
    data = db.execute('SELECT * FROM materials').fetchall()
    db.close()
    return render_template('materials.html', materials=data)


@app.route('/materials/add', methods=['POST'])
@admin_required
def add_material():
    name = request.form.get('name', '').strip()
    unit = request.form.get('unit', 'pcs')
    if not name:
        flash('Name is required.', 'danger')
        return redirect(url_for('materials'))
    try:
        quantity = int(request.form.get('quantity', 0))
    except ValueError:
        flash('Quantity must be a number.', 'danger')
        return redirect(url_for('materials'))
    db = get_db()
    db.execute('INSERT INTO materials (name,quantity,unit) VALUES (?,?,?)', (name, quantity, unit))
    db.execute("INSERT INTO activity (message) VALUES (?)", (f"Material '{name}' added",))
    db.commit()
    db.close()
    flash(f"Material '{name}' added.", 'success')
    return redirect(url_for('materials'))


@app.route('/materials/use/<int:mid>', methods=['POST'])
@admin_required
def use_material(mid):
    try:
        amount = int(request.form.get('amount', 0))
    except ValueError:
        flash('Amount must be a number.', 'danger')
        return redirect(url_for('materials'))
    if amount <= 0:
        flash('Amount must be > 0.', 'danger')
        return redirect(url_for('materials'))
    db = get_db()
    mat = db.execute('SELECT * FROM materials WHERE id=?', (mid,)).fetchone()
    if not mat:
        flash('Not found.', 'danger')
        db.close()
        return redirect(url_for('materials'))
    if mat['quantity'] < amount:
        flash(f"Not enough stock. Available: {mat['quantity']} {mat['unit']}.", 'danger')
        db.close()
        return redirect(url_for('materials'))
    db.execute('UPDATE materials SET used=?,quantity=? WHERE id=?',
               (mat['used'] + amount, mat['quantity'] - amount, mid))
    db.execute("INSERT INTO activity (message) VALUES (?)",
               (f"Used {amount} {mat['unit']} of '{mat['name']}'",))
    db.commit()
    db.close()
    flash(f"Used {amount} {mat['unit']} of '{mat['name']}'.", 'success')
    return redirect(url_for('materials'))


@app.route('/materials/delete/<int:mid>')
@admin_required
def delete_material(mid):
    db = get_db()
    row = db.execute('SELECT name FROM materials WHERE id=?', (mid,)).fetchone()
    if row:
        db.execute('DELETE FROM materials WHERE id=?', (mid,))
        db.execute("INSERT INTO activity (message) VALUES (?)", (f"Material '{row['name']}' deleted",))
        db.commit()
        flash(f"Material '{row['name']}' deleted.", 'success')
    db.close()
    return redirect(url_for('materials'))


# ─── FILE UPLOAD ──────────────────────────────────────────────────────────────
@app.route('/upload', methods=['GET', 'POST'])
@admin_required
def upload_file():
    db = get_db()
    if request.method == 'POST':
        job_id    = request.form.get('job_id') or None
        file_type = request.form.get('file_type', 'image')
        if 'file' not in request.files:
            flash('No file selected.', 'danger')
            return redirect(url_for('upload_file'))
        file = request.files['file']
        if not file or not file.filename:
            flash('No file selected.', 'danger')
            return redirect(url_for('upload_file'))
        if not allowed_file(file.filename):
            flash('File type not allowed.', 'danger')
            return redirect(url_for('upload_file'))
        filename  = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)
        db.execute('''INSERT INTO uploads (filename,original_name,file_type,job_id,uploaded_by)
                      VALUES (?,?,?,?,?)''',
                   (filename, file.filename, file_type, job_id, session['user_id']))
        db.execute("INSERT INTO activity (message) VALUES (?)", (f"File '{filename}' uploaded",))
        db.commit()
        flash(f"File '{file.filename}' uploaded.", 'success')
    uploads    = db.execute('''SELECT uploads.*, jobs.title AS job_title
                               FROM uploads LEFT JOIN jobs ON uploads.job_id = jobs.id
                               ORDER BY uploads.id DESC''').fetchall()
    jobs_list  = db.execute('SELECT * FROM jobs').fetchall()
    db.close()
    return render_template('upload.html', uploads=uploads, jobs=jobs_list)


# ─── REPORTS ──────────────────────────────────────────────────────────────────
@app.route('/reports')
@admin_required
def reports():
    db = get_db()
    pending   = db.execute("SELECT COUNT(*) FROM tasks WHERE status='Pending'").fetchone()[0]
    in_prog   = db.execute("SELECT COUNT(*) FROM tasks WHERE status='In Progress'").fetchone()[0]
    completed = db.execute("SELECT COUNT(*) FROM tasks WHERE status='Completed'").fetchone()[0]
    elec_activity = db.execute('''
        SELECT electricians.name,
               COUNT(tasks.id) AS total_tasks,
               SUM(CASE WHEN tasks.status='Completed' THEN 1 ELSE 0 END) AS done
        FROM electricians LEFT JOIN tasks ON tasks.electrician_id = electricians.id
        GROUP BY electricians.id
    ''').fetchall()
    activity      = db.execute('SELECT * FROM activity ORDER BY id DESC LIMIT 10').fetchall()
    jobs_pending  = db.execute("SELECT COUNT(*) FROM jobs WHERE status='Pending'").fetchone()[0]
    jobs_inprog   = db.execute("SELECT COUNT(*) FROM jobs WHERE status='In Progress'").fetchone()[0]
    jobs_completed = db.execute("SELECT COUNT(*) FROM jobs WHERE status='Completed'").fetchone()[0]
    db.close()
    return render_template('reports.html',
        pending=pending, in_prog=in_prog, completed=completed,
        elec_activity=elec_activity, activity=activity,
        jobs_pending=jobs_pending, jobs_inprog=jobs_inprog, jobs_completed=jobs_completed
    )


# ─── NOTIFICATIONS ────────────────────────────────────────────────────────────
@app.route('/notifications')
@login_required
def notifications():
    notes = get_notifications()
    return render_template('notifications.html', notifications=notes)


# ─── PROFILE ──────────────────────────────────────────────────────────────────
@app.route('/profile')
@login_required
def profile():
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    db.close()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('logout'))
    return render_template('profile.html', user=user)


# ═══════════════════════════════════════════════════════════════════════════════
# WEEK 6 — PAYMENT GATEWAY ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

# ─── CLIENT PAYMENT PAGE (public — no login required) ─────────────────────────
@app.route('/jobs/<int:jid>/pay')
def client_pay(jid):
    """
    Public payment page that admin shares with the client.
    The client sees job details and a Razorpay checkout button.
    """
    db = get_db()
    job = db.execute('SELECT * FROM jobs WHERE id=?', (jid,)).fetchone()
    db.close()
    if not job:
        return "Job not found.", 404
    if job['payment_status'] == 'Paid':
        return render_template('payment_already_paid.html', job=job)
    return render_template('payment.html',
                           job=job,
                           razorpay_key=RAZORPAY_KEY_ID,
                           razorpay_available=RAZORPAY_AVAILABLE)


# ─── CREATE RAZORPAY ORDER (JSON API) ─────────────────────────────────────────
@app.route('/api/create-order', methods=['POST'])
def create_order():
    """
    Called by the payment page JS to create a Razorpay order.
    Returns: { order_id, amount, currency, key_id }
    """
    data   = request.get_json()
    job_id = data.get('job_id')

    db = get_db()
    job = db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
    db.close()

    if not job:
        return jsonify({'error': 'Job not found'}), 404
    if job['amount'] <= 0:
        return jsonify({'error': 'No amount set for this job'}), 400

    amount_paise = int(float(job['amount']) * 100)  # Razorpay uses paise (1 INR = 100 paise)

    if RAZORPAY_AVAILABLE and RAZORPAY_KEY_ID != 'rzp_test_REPLACE_ME':
        # Real Razorpay order
        try:
            client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
            order  = client.order.create({
                'amount':   amount_paise,
                'currency': 'INR',
                'receipt':  f'job_{job_id}',
                'notes':    {'job_title': job['title']}
            })
            order_id = order['id']
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        # Demo mode — simulate an order ID
        import uuid
        order_id = f'order_DEMO_{uuid.uuid4().hex[:10].upper()}'

    # Pre-create payment record with pending status
    db = get_db()
    db.execute('''INSERT INTO payments
                  (job_id, amount, payment_type, razorpay_order_id, status, payer_name, payer_email)
                  VALUES (?,?,?,?,?,?,?)''',
               (job_id, job['amount'], 'client_to_admin', order_id, 'pending',
                job['client_name'], job['client_email']))
    db.commit()
    db.close()

    return jsonify({
        'order_id': order_id,
        'amount':   amount_paise,
        'currency': 'INR',
        'key_id':   RAZORPAY_KEY_ID,
        'job_title': job['title'],
        'client_name': job['client_name'] or '',
        'client_email': job['client_email'] or '',
        'demo_mode': not (RAZORPAY_AVAILABLE and RAZORPAY_KEY_ID != 'rzp_test_REPLACE_ME')
    })


# ─── VERIFY RAZORPAY PAYMENT ──────────────────────────────────────────────────
@app.route('/api/verify-payment', methods=['POST'])
def verify_payment():
    """
    Called after Razorpay checkout completes.
    Verifies HMAC signature, marks payment as success, updates job.
    """
    data               = request.get_json()
    order_id           = data.get('razorpay_order_id')
    payment_id         = data.get('razorpay_payment_id')
    signature          = data.get('razorpay_signature')
    job_id             = data.get('job_id')
    payer_name         = data.get('payer_name', '')
    payer_email        = data.get('payer_email', '')

    is_demo = data.get('demo_mode', False)

    if not is_demo and RAZORPAY_AVAILABLE and RAZORPAY_KEY_ID != 'rzp_test_REPLACE_ME':
        # Verify signature (security check)
        body    = f"{order_id}|{payment_id}"
        expected = hmac.new(
            RAZORPAY_KEY_SECRET.encode('utf-8'),
            body.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return jsonify({'success': False, 'error': 'Signature verification failed'}), 400

    # Mark payment as success
    db = get_db()
    db.execute('''UPDATE payments
                  SET razorpay_payment_id=?, razorpay_signature=?, status='success',
                      payer_name=?, payer_email=?
                  WHERE razorpay_order_id=?''',
               (payment_id, signature, payer_name, payer_email, order_id))
    # Update job payment status
    db.execute("UPDATE jobs SET payment_status='Paid' WHERE id=?", (job_id,))
    db.execute("INSERT INTO activity (message) VALUES (?)",
               (f"Payment received for Job #{job_id} — ₹{data.get('amount', '')} — {payer_name}",))
    db.commit()
    db.close()

    return jsonify({'success': True, 'redirect': url_for('payment_success', job_id=job_id)})


# ─── PAYMENT SUCCESS / FAILURE PAGES ─────────────────────────────────────────
@app.route('/payment/success')
def payment_success():
    job_id = request.args.get('job_id')
    db     = get_db()
    job    = db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone() if job_id else None
    db.close()
    return render_template('payment_success.html', job=job)


@app.route('/payment/failure')
def payment_failure():
    job_id = request.args.get('job_id')
    db     = get_db()
    job    = db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone() if job_id else None
    # Mark as failed in DB
    if job_id:
        db = get_db()
        db.execute('''UPDATE payments SET status='failed'
                      WHERE job_id=? AND status='pending'
                      ORDER BY id DESC LIMIT 1''', (job_id,))
        db.commit()
        db.close()
    return render_template('payment_failure.html', job=job)


# ─── ADMIN PAYS ELECTRICIAN ───────────────────────────────────────────────────
@app.route('/admin/pay-electrician/<int:jid>', methods=['POST'])
@admin_required
def pay_electrician(jid):
    """
    Admin records a disbursement to electrician after job completion.
    This is a manual/simulated payment (recorded in DB as proof).
    """
    try:
        amount = float(request.form.get('amount', 0) or 0)
    except ValueError:
        amount = 0.0
    notes = request.form.get('notes', '').strip()

    if amount <= 0:
        flash('Please enter a valid amount.', 'danger')
        return redirect(url_for('transactions'))

    db  = get_db()
    job = db.execute('SELECT * FROM jobs WHERE id=?', (jid,)).fetchone()
    if not job:
        flash('Job not found.', 'danger')
        db.close()
        return redirect(url_for('transactions'))

    # Find electrician for this job
    electrician = None
    if job['electrician_id']:
        electrician = db.execute('SELECT * FROM electricians WHERE id=?',
                                 (job['electrician_id'],)).fetchone()

    import uuid
    fake_payment_id = f'PAY_ELEC_{uuid.uuid4().hex[:8].upper()}'

    db.execute('''INSERT INTO payments
                  (job_id, amount, payment_type, razorpay_payment_id, status, payer_name, notes)
                  VALUES (?,?,?,?,?,?,?)''',
               (jid, amount, 'admin_to_electrician', fake_payment_id, 'success',
                electrician['name'] if electrician else 'Unknown', notes))
    db.execute("INSERT INTO activity (message) VALUES (?)",
               (f"Admin paid ₹{amount} to {electrician['name'] if electrician else 'electrician'} for Job #{jid}",))
    db.commit()
    db.close()

    flash(f"Payment of ₹{amount:.2f} recorded for {electrician['name'] if electrician else 'electrician'}.", 'success')
    return redirect(url_for('transactions'))


# ─── TRANSACTION HISTORY ──────────────────────────────────────────────────────
@app.route('/transactions')
@admin_required
def transactions():
    """Full payment audit log for admin."""
    db     = get_db()
    filter_type   = request.args.get('type', 'All')
    filter_status = request.args.get('status', 'All')

    query  = '''SELECT payments.*, jobs.title AS job_title, jobs.electrician_id
                FROM payments LEFT JOIN jobs ON payments.job_id = jobs.id
                WHERE 1=1'''
    params = []
    if filter_type != 'All':
        query += ' AND payments.payment_type=?'
        params.append(filter_type)
    if filter_status != 'All':
        query += ' AND payments.status=?'
        params.append(filter_status)
    query += ' ORDER BY payments.id DESC'

    txns  = db.execute(query, params).fetchall()
    jobs_list = db.execute("SELECT * FROM jobs WHERE electrician_id IS NOT NULL").fetchall()

    # Summary stats
    total_received = db.execute(
        "SELECT COALESCE(SUM(amount),0) FROM payments WHERE payment_type='client_to_admin' AND status='success'"
    ).fetchone()[0]
    total_paid_out = db.execute(
        "SELECT COALESCE(SUM(amount),0) FROM payments WHERE payment_type='admin_to_electrician' AND status='success'"
    ).fetchone()[0]
    pending_count  = db.execute(
        "SELECT COUNT(*) FROM payments WHERE status='pending'"
    ).fetchone()[0]
    db.close()

    return render_template('transactions.html',
                           transactions=txns,
                           jobs=jobs_list,
                           total_received=total_received,
                           total_paid_out=total_paid_out,
                           pending_count=pending_count,
                           filter_type=filter_type,
                           filter_status=filter_status)


# ─── JSON API ─────────────────────────────────────────────────────────────────
@app.route('/api/stats')
@admin_required
def api_stats():
    db   = get_db()
    data = {
        'electricians': db.execute('SELECT COUNT(*) FROM electricians').fetchone()[0],
        'jobs': {
            'total':       db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],
            'pending':     db.execute("SELECT COUNT(*) FROM jobs WHERE status='Pending'").fetchone()[0],
            'in_progress': db.execute("SELECT COUNT(*) FROM jobs WHERE status='In Progress'").fetchone()[0],
            'completed':   db.execute("SELECT COUNT(*) FROM jobs WHERE status='Completed'").fetchone()[0],
        },
        'tasks': {
            'total':       db.execute('SELECT COUNT(*) FROM tasks').fetchone()[0],
            'pending':     db.execute("SELECT COUNT(*) FROM tasks WHERE status='Pending'").fetchone()[0],
            'in_progress': db.execute("SELECT COUNT(*) FROM tasks WHERE status='In Progress'").fetchone()[0],
            'completed':   db.execute("SELECT COUNT(*) FROM tasks WHERE status='Completed'").fetchone()[0],
        },
        'materials':       db.execute('SELECT COUNT(*) FROM materials').fetchone()[0],
        'revenue': {
            'collected': db.execute(
                "SELECT COALESCE(SUM(amount),0) FROM payments WHERE payment_type='client_to_admin' AND status='success'"
            ).fetchone()[0],
            'disbursed': db.execute(
                "SELECT COALESCE(SUM(amount),0) FROM payments WHERE payment_type='admin_to_electrician' AND status='success'"
            ).fetchone()[0],
        }
    }
    db.close()
    return jsonify({'success': True, 'data': data})


@app.route('/api/tasks')
@admin_required
def api_tasks():
    db   = get_db()
    rows = db.execute('''
        SELECT tasks.id, tasks.task, tasks.status,
               jobs.title AS job, electricians.name AS electrician
        FROM tasks
        LEFT JOIN jobs ON tasks.job_id = jobs.id
        LEFT JOIN electricians ON tasks.electrician_id = electricians.id
    ''').fetchall()
    db.close()
    return jsonify({'success': True, 'data': [dict(r) for r in rows]})


@app.route('/api/jobs')
@admin_required
def api_jobs():
    db   = get_db()
    rows = db.execute('''
        SELECT jobs.id, jobs.title, jobs.location, jobs.deadline,
               jobs.status, jobs.amount, jobs.payment_status,
               electricians.name AS electrician
        FROM jobs LEFT JOIN electricians ON jobs.electrician_id = electricians.id
    ''').fetchall()
    db.close()
    return jsonify({'success': True, 'data': [dict(r) for r in rows]})


@app.route('/api/transactions')
@admin_required
def api_transactions():
    db   = get_db()
    rows = db.execute('''
        SELECT payments.*, jobs.title AS job_title
        FROM payments LEFT JOIN jobs ON payments.job_id = jobs.id
        ORDER BY payments.id DESC
    ''').fetchall()
    db.close()
    return jsonify({'success': True, 'data': [dict(r) for r in rows]})


# ─── ERROR HANDLERS ───────────────────────────────────────────────────────────
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(413)
def file_too_large(e):
    flash('File too large. Max 5MB.', 'danger')
    return redirect(url_for('upload_file'))


# ─── RUN ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True)