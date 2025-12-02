from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required
from ..models import User
from ..extensions import db

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# -----------------------
# Login selection page
# -----------------------
@auth_bp.route("/login_select")
def login_select():
    return render_template("login_select.html")


# -----------------------
# Register
# -----------------------
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        role = request.form.get("role")   # added for role-based login

        if User.query.filter_by(username=username).first():
            flash("Username already exists")
            return redirect(url_for("auth.register"))

        user = User(username=username, role=role)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        flash("User registered successfully")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


# -----------------------
# Login
# -----------------------
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)

            # Role-based redirects
            if user.role == "admin":
                return redirect(url_for("admin.dashboard"))
            elif user.role == "doctor":
                return redirect(url_for("doctor.dashboard"))
            elif user.role == "nurse":
                return redirect(url_for("nurse.dashboard"))
            else:
                return redirect(url_for("patient.dashboard"))

        flash("Invalid username or password")

    return render_template("login.html")   # actual login form


# -----------------------
# Logout
# -----------------------
@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))