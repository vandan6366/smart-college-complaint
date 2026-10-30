import os
import secrets
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-development-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    "mysql+pymysql://root:YOUR_MYSQL_PASSWORD@localhost/smart_college_complaints?charset=utf8mb4"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

CATEGORIES = [
    "Classroom / Laboratory", "Hostel", "Canteen", "Water / Electricity",
    "Internet / Wi-Fi", "Cleanliness / Maintenance", "Harassment / Confidential",
    "Other"
]
STATUSES = ["Submitted", "Assigned", "In Progress", "Resolved", "Rejected"]

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="student")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    complaints = db.relationship("Complaint", backref="student", lazy=True)

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tracking_code = db.Column(db.String(20), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    category = db.Column(db.String(80), nullable=False)
    department = db.Column(db.String(80), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), nullable=False, default="Normal")
    status = db.Column(db.String(30), nullable=False, default="Submitted")
    admin_remarks = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(24)
    return session["_csrf"]
app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def protect_post_requests():
    if request.method == "POST":
        submitted = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not submitted or not expected or not secrets.compare_digest(submitted, expected):
            abort(400, description="Invalid or expired form token. Please go back and try again.")

@app.context_processor
def inject_user():
    user = db.session.get(User, session.get("user_id")) if session.get("user_id") else None
    return {"current_user": user, "categories": CATEGORIES, "statuses": STATUSES}

@app.route("/")
def index():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    if session.get("user_id"):
        return redirect(url_for("student_dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or len(password) < 8:
            flash("Enter your name and email, and use a password with at least 8 characters.", "danger")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("That email is already registered. Please log in.", "warning")
            return redirect(url_for("login"))
        user = User(name=name, email=email, password_hash=generate_password_hash(password), role="student")
        db.session.add(user)
        db.session.commit()
        flash("Account created. You can now log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session["user_id"] = user.id
            session["role"] = user.role
            session["_csrf"] = secrets.token_urlsafe(24)
            return redirect(url_for("admin_dashboard" if user.role == "admin" else "student_dashboard"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("login"))

@app.route("/student")
@login_required
def student_dashboard():
    if session.get("role") != "student":
        return redirect(url_for("admin_dashboard"))
    complaints = Complaint.query.filter_by(user_id=session["user_id"]).order_by(Complaint.created_at.desc()).all()
    counts = {
        "total": len(complaints),
        "pending": sum(c.status not in ("Resolved", "Rejected") for c in complaints),
        "resolved": sum(c.status == "Resolved" for c in complaints),
    }
    return render_template("student.html", complaints=complaints, counts=counts)

@app.route("/complaints/new", methods=["GET", "POST"])
@login_required
def new_complaint():
    if session.get("role") != "student":
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        category = request.form.get("category", "")
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        priority = request.form.get("priority", "Normal")
        if category not in CATEGORIES or not title or not description:
            flash("Please complete all required fields.", "danger")
            return render_template("new_complaint.html")
        if priority not in ("Low", "Normal", "High"):
            priority = "Normal"
        department_map = {
            "Classroom / Laboratory": "Academic / Lab",
            "Hostel": "Hostel Office",
            "Canteen": "Canteen Management",
            "Water / Electricity": "Facilities",
            "Internet / Wi-Fi": "IT Support",
            "Cleanliness / Maintenance": "Facilities",
            "Harassment / Confidential": "Student Welfare",
            "Other": "College Administration",
        }
        code = "CC-" + secrets.token_hex(4).upper()
        complaint = Complaint(
            tracking_code=code, user_id=session["user_id"], category=category,
            department=department_map.get(category, "College Administration"),
            title=title, description=description, priority=priority
        )
        db.session.add(complaint)
        db.session.commit()
        flash(f"Complaint submitted successfully. Tracking ID: {code}", "success")
        return redirect(url_for("student_dashboard"))
    return render_template("new_complaint.html")

@app.route("/admin")
@admin_required
def admin_dashboard():
    status_filter = request.args.get("status", "")
    query = Complaint.query
    if status_filter in STATUSES:
        query = query.filter_by(status=status_filter)
    complaints = query.order_by(Complaint.created_at.desc()).all()
    all_complaints = Complaint.query.all()
    counts = {
        "total": len(all_complaints),
        "pending": sum(c.status not in ("Resolved", "Rejected") for c in all_complaints),
        "resolved": sum(c.status == "Resolved" for c in all_complaints),
    }
    return render_template("admin.html", complaints=complaints, counts=counts, status_filter=status_filter)

@app.route("/admin/complaints/<int:complaint_id>/update", methods=["POST"])
@admin_required
def update_complaint(complaint_id):
    complaint = db.session.get(Complaint, complaint_id)
    if not complaint:
        abort(404)
    status = request.form.get("status", "")
    remarks = request.form.get("admin_remarks", "").strip()
    if status not in STATUSES:
        flash("Invalid complaint status.", "danger")
    else:
        complaint.status = status
        complaint.admin_remarks = remarks[:2000] or None
        complaint.updated_at = datetime.utcnow()
        db.session.commit()
        flash(f"{complaint.tracking_code} updated.", "success")
    return redirect(url_for("admin_dashboard"))

@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You do not have permission to view this page."), 403

@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="The page or complaint could not be found."), 404

@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=getattr(error, "description", "Invalid request.")), 400

def create_admin():
    email = os.environ.get("ADMIN_EMAIL", "admin@college.edu").strip().lower()
    password = os.environ.get("ADMIN_PASSWORD", "ChangeMe123!")
    existing = User.query.filter_by(email=email).first()
    if not existing:
        db.session.add(User(
            name="College Administrator",
            email=email,
            password_hash=generate_password_hash(password),
            role="admin"
        ))
        db.session.commit()
        print(f"Created demo admin account: {email}")
        if password == "ChangeMe123!":
            print("IMPORTANT: Change the demo admin password before using this outside your laptop.")

with app.app_context():
    db.create_all()
    create_admin()

if __name__ == "__main__":
    app.run(debug=True)
