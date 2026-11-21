
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, request, abort,
    send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pathlib import Path
from datetime import datetime
import sqlite3
import secrets
import os
import re

app = Flask(__name__)

BASE = Path(__file__).resolve().parent
DATABASE = BASE / "campus_submit.db"
UPLOADS = BASE / "uploads"
UPLOADS.mkdir(exist_ok=True)

app.secret_key = os.environ.get(
    "CAMPUS_SECRET_KEY",
    "development-only-change-this-secret"
)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

ALLOWED = {"pdf", "doc", "docx", "ppt", "pptx", "txt"}


# DATABASE
def db():
    con = sqlite3.connect(DATABASE)
    con.row_factory = sqlite3.Row
    return con


def initialize():
    with db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                semester TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                approval_status TEXT NOT NULL DEFAULT 'Approved'
            )
        """)

        con.execute("""
            CREATE TABLE IF NOT EXISTS assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                semester TEXT NOT NULL,
                deadline TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        con.execute("""
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student TEXT NOT NULL,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL UNIQUE,
                submitted_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Submitted',
                assignment_id INTEGER,
                feedback TEXT DEFAULT '',
                reviewed_at TEXT
            )
        """)

        # Add new columns to an existing database.
        columns = {
            row["name"]
            for row in con.execute("PRAGMA table_info(submissions)")
        }

        for column, definition in {
            "assignment_id": "INTEGER",
            "feedback": "TEXT DEFAULT ''",
            "reviewed_at": "TEXT"
        }.items():
            if column not in columns:
                con.execute(
                    f"ALTER TABLE submissions ADD COLUMN {column} {definition}"
                )

        # Preserve old accounts, but allow them to log in.
        con.execute("""
            UPDATE users SET approval_status='Approved'
            WHERE approval_status IS NULL
               OR approval_status != 'Approved'
        """)


# LOGIN HELPERS
def current_user():
    username = session.get("username")
    if not username:
        return None

    with db() as con:
        return con.execute(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE",
            (username,)
        ).fetchone()


def require_role(role):
    user = current_user()
    return user is not None and user["role"] == role


@app.before_request
def prepare_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)


@app.context_processor
def template_data():
    return {"csrf_token": session.get("csrf_token", "")}


def check_token():
    token = session.get("csrf_token", "")
    submitted = request.form.get("csrf_token", "")
    return bool(token) and secrets.compare_digest(token, submitted)


def now_string():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# HOME
@app.route("/")
def home():
    user = current_user()
    if user:
        return redirect(
            url_for("faculty" if user["role"] == "faculty" else "student")
        )
    return render_template("login.html")


# REGISTER STUDENT OR FACULTY
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    if not check_token():
        abort(400)

    name = request.form.get("full_name", "").strip()
    username = request.form.get("username", "").strip().upper()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")
    role = request.form.get("role", "")
    semester = request.form.get("semester", "").strip()

    if role not in ("student", "faculty"):
        flash("Select Student or Faculty.", "error")
        return redirect(url_for("register"))

    if role == "faculty":
        semester = "N/A"

    if not (
        1 <= len(name) <= 100
        and re.fullmatch(r"[A-Z0-9_]{3,30}", username)
        and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
        and len(email) <= 254
        and 8 <= len(password) <= 128
        and password == confirm
        and (role == "faculty" or semester in [str(i) for i in range(1, 9)])
    ):
        flash("Please check your details and passwords.", "error")
        return redirect(url_for("register"))

    try:
        with db() as con:
            con.execute("""
                INSERT INTO users
                (username, full_name, email, semester,
                 password_hash, role, approval_status)
                VALUES (?, ?, ?, ?, ?, ?, 'Approved')
            """, (
                username, name, email, semester,
                generate_password_hash(password), role
            ))
    except sqlite3.IntegrityError:
        flash("Username or email is already registered.", "error")
        return redirect(url_for("register"))

    flash("Registration successful! You can log in now.", "success")
    return redirect(url_for("home"))


# LOGIN
@app.route("/login", methods=["POST"])
def login():
    if not check_token():
        abort(400)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    with db() as con:
        user = con.execute(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE",
            (username,)
        ).fetchone()

    if not user or not check_password_hash(
        user["password_hash"], password
    ):
        flash("Invalid username or password.", "error")
        return redirect(url_for("home"))

    session.clear()
    session["username"] = user["username"]
    session["csrf_token"] = secrets.token_hex(32)

    return redirect(
        url_for("faculty" if user["role"] == "faculty" else "student")
    )


# STUDENT DASHBOARD
@app.route("/student")
def student():
    if not require_role("student"):
        return redirect(url_for("home"))

    user = current_user()

    with db() as con:
        assignments = con.execute("""
            SELECT a.*,
                   s.id AS submission_id,
                   s.status AS submission_status,
                   s.original_name,
                   s.feedback,
                   s.submitted_at
            FROM assignments a
            LEFT JOIN submissions s
                ON s.assignment_id = a.id
               AND s.student = ?
            WHERE a.semester = ? OR a.semester = 'All'
            ORDER BY a.deadline ASC
        """, (user["username"], user["semester"])).fetchall()

        history = con.execute("""
            SELECT * FROM submissions
            WHERE student=?
            ORDER BY id DESC
        """, (user["username"],)).fetchall()

    return render_template(
        "student.html",
        user=user,
        assignments=assignments,
        history=history,
        now=datetime.now().strftime("%Y-%m-%dT%H:%M")
    )


# STUDENT UPLOAD
@app.route("/upload", methods=["POST"])
def upload():
    if not require_role("student"):
        abort(403)
    if not check_token():
        abort(400)

    user = current_user()

    try:
        assignment_id = int(request.form.get("assignment_id", ""))
    except ValueError:
        abort(400)

    with db() as con:
        assignment = con.execute(
            "SELECT * FROM assignments WHERE id=?",
            (assignment_id,)
        ).fetchone()

        existing = con.execute("""
            SELECT id FROM submissions
            WHERE student=? AND assignment_id=?
        """, (user["username"], assignment_id)).fetchone()

    if not assignment:
        abort(404)

    if assignment["semester"] not in ("All", user["semester"]):
        abort(403)

    if existing:
        flash("You have already submitted this assignment.", "error")
        return redirect(url_for("student"))

    if datetime.now() > datetime.fromisoformat(assignment["deadline"]):
        flash("The deadline has passed.", "error")
        return redirect(url_for("student"))

    file = request.files.get("assignment")

    if (
        not file
        or not file.filename
        or "." not in file.filename
        or file.filename.rsplit(".", 1)[1].lower() not in ALLOWED
    ):
        flash("Please choose a valid assignment file.", "error")
        return redirect(url_for("student"))

    original = secure_filename(file.filename)
    if not original:
        abort(400)

    stored = secrets.token_hex(16) + "_" + original
    path = UPLOADS / stored
    file.save(path)

    try:
        with db() as con:
            con.execute("""
                INSERT INTO submissions
                (student, original_name, stored_name,
                 submitted_at, status, assignment_id)
                VALUES (?, ?, ?, ?, 'Submitted', ?)
            """, (
                user["username"], original, stored,
                now_string(), assignment_id
            ))
    except sqlite3.Error:
        path.unlink(missing_ok=True)
        flash("Unable to save the submission.", "error")
        return redirect(url_for("student"))

    flash("Assignment submitted successfully!", "success")
    return redirect(url_for("student"))


# FACULTY DASHBOARD
@app.route("/faculty")
def faculty():
    if not require_role("faculty"):
        return redirect(url_for("home"))

    with db() as con:
        assignments = con.execute("""
            SELECT * FROM assignments
            ORDER BY id DESC
        """).fetchall()

        submissions = con.execute("""
            SELECT s.*, a.title AS assignment_title
            FROM submissions s
            LEFT JOIN assignments a ON s.assignment_id=a.id
            ORDER BY s.id DESC
        """).fetchall()

    return render_template(
        "faculty.html",
        assignments=assignments,
        submissions=submissions
    )


# FACULTY CREATES AN ASSIGNMENT
@app.route("/create_assignment", methods=["POST"])
def create_assignment():
    if not require_role("faculty"):
        abort(403)
    if not check_token():
        abort(400)

    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    semester = request.form.get("semester", "").strip()
    deadline = request.form.get("deadline", "").strip()

    if (
        not title or len(title) > 150
        or not description or len(description) > 3000
        or semester not in ["All"] + [str(i) for i in range(1, 9)]
    ):
        flash("Enter valid assignment details.", "error")
        return redirect(url_for("faculty"))

    try:
        deadline_date = datetime.fromisoformat(deadline)
        if deadline_date <= datetime.now():
            raise ValueError()
    except ValueError:
        flash("Choose a valid future deadline.", "error")
        return redirect(url_for("faculty"))

    user = current_user()

    with db() as con:
        con.execute("""
            INSERT INTO assignments
            (title, description, semester, deadline, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            title, description, semester,
            deadline, user["username"], now_string()
        ))

    flash("Assignment created successfully!", "success")
    return redirect(url_for("faculty"))


# FACULTY REVIEWS A SUBMISSION
@app.route("/review/<int:submission_id>", methods=["POST"])
def review_submission(submission_id):
    if not require_role("faculty"):
        abort(403)
    if not check_token():
        abort(400)

    feedback = request.form.get("feedback", "").strip()

    if len(feedback) > 2000:
        flash("Feedback is too long.", "error")
        return redirect(url_for("faculty"))

    with db() as con:
        changed = con.execute("""
            UPDATE submissions
            SET status='Reviewed',
                feedback=?,
                reviewed_at=?
            WHERE id=?
        """, (feedback, now_string(), submission_id)).rowcount

    if not changed:
        abort(404)

    flash("Assignment reviewed successfully!", "success")
    return redirect(url_for("faculty"))


# DOWNLOAD
@app.route("/download/<int:submission_id>")
def download_assignment(submission_id):
    user = current_user()
    if not user:
        abort(403)

    with db() as con:
        submission = con.execute(
            "SELECT * FROM submissions WHERE id=?",
            (submission_id,)
        ).fetchone()

    if not submission:
        abort(404)

    if (
        user["role"] != "faculty"
        and submission["student"] != user["username"]
    ):
        abort(403)

    return send_from_directory(
        str(UPLOADS),
        submission["stored_name"],
        as_attachment=True,
        download_name=submission["original_name"]
    )


# LOGOUT
@app.route("/logout", methods=["POST"])
def logout():
    if not check_token():
        abort(400)

    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("home"))


@app.errorhandler(413)
def too_large(error):
    flash("Maximum file size is 10 MB.", "error")
    return redirect(url_for("home"))


initialize()

if __name__ == "__main__":
    print("Running:", __file__)
    print(app.url_map)
    app.run(debug=True)
