"""
database.py - FieldOps Manager
Week 6: Added payments table, amount/client info in jobs, payment_status tracking.
"""

import sqlite3

DATABASE = 'fieldops.db'


def get_db():
    """Return a new database connection with row factory enabled."""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    """Create all tables if they don't already exist. Safe to call on every startup."""
    db = get_db()

    # Users
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT,
        email TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL DEFAULT 'electrician',
        password TEXT NOT NULL
    )''')

    # Electricians
    db.execute('''CREATE TABLE IF NOT EXISTS electricians (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT,
        email TEXT,
        specialization TEXT,
        status TEXT DEFAULT 'Active',
        rating REAL DEFAULT 0.0
    )''')

    # Jobs — Week 6 added: amount, client_name, client_email, payment_status
    db.execute('''CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        location TEXT,
        deadline TEXT,
        electrician_id INTEGER,
        status TEXT DEFAULT 'Pending',
        image_filename TEXT,
        amount REAL DEFAULT 0.0,
        client_name TEXT DEFAULT '',
        client_email TEXT DEFAULT '',
        payment_status TEXT DEFAULT 'Unpaid',
        FOREIGN KEY (electrician_id) REFERENCES electricians(id)
    )''')

    # Tasks
    db.execute('''CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task TEXT NOT NULL,
        job_id INTEGER,
        electrician_id INTEGER,
        status TEXT DEFAULT 'Pending',
        FOREIGN KEY (job_id) REFERENCES jobs(id),
        FOREIGN KEY (electrician_id) REFERENCES electricians(id)
    )''')

    # Materials
    db.execute('''CREATE TABLE IF NOT EXISTS materials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        quantity INTEGER DEFAULT 0,
        used INTEGER DEFAULT 0,
        unit TEXT DEFAULT 'pcs'
    )''')

    # Activity log
    db.execute('''CREATE TABLE IF NOT EXISTS activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')

    # Uploads
    db.execute('''CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        original_name TEXT,
        file_type TEXT,
        job_id INTEGER,
        uploaded_by INTEGER,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (job_id) REFERENCES jobs(id),
        FOREIGN KEY (uploaded_by) REFERENCES users(id)
    )''')

    # ── WEEK 6: Payments ──────────────────────────────────────────────────────
    # payment_type: 'client_to_admin' or 'admin_to_electrician'
    # status: 'pending' | 'success' | 'failed'
    db.execute('''CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER,
        amount REAL NOT NULL,
        payment_type TEXT NOT NULL,
        razorpay_order_id TEXT,
        razorpay_payment_id TEXT,
        razorpay_signature TEXT,
        status TEXT DEFAULT 'pending',
        payer_name TEXT,
        payer_email TEXT,
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (job_id) REFERENCES jobs(id)
    )''')

    # ── Migrate existing jobs table if upgrading from Week 5 ──────────────────
    # SQLite doesn't support IF NOT EXISTS on ALTER TABLE, so we try/ignore
    for col_def in [
        "ALTER TABLE jobs ADD COLUMN amount REAL DEFAULT 0.0",
        "ALTER TABLE jobs ADD COLUMN client_name TEXT DEFAULT ''",
        "ALTER TABLE jobs ADD COLUMN client_email TEXT DEFAULT ''",
        "ALTER TABLE jobs ADD COLUMN payment_status TEXT DEFAULT 'Unpaid'",
    ]:
        try:
            db.execute(col_def)
        except Exception:
            pass  # Column already exists — safe to ignore

    db.commit()
    db.close()