from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required
from werkzeug.security import check_password_hash
from ..models import User
from ..extensions import db

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

@auth_bp.route("/login_select")
def login_select():
    return render_template("login_select.html")

@auth_bp.route("/register")
def register():
    ...

auth_bp = Blueprint("auth", __name__, template_folder="../templates")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)

            # Redirect by ROLE
            if user.role == "admin":
                return redirect(url_for("admin.dashboard"))
            elif user.role == "doctor":
                return redirect(url_for("doctor.dashboard"))
            elif user.role == "nurse":
                return redirect(url_for("nurse.dashboard"))
            else:
                return redirect(url_for("patient.dashboard"))

        flash("Invalid username or password")
    return render_template("login_select.html")

@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))