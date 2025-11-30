from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User, StrokeRecord, db
import pandas as pd

bp = Blueprint("main", __name__)

@bp.route("/")
def home():
    return "Flask app working successfully!"

@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("User already exists!", "danger")
            return redirect(url_for("main.register"))

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("main.login"))

    return render_template("register.html")

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("main.home"))
        else:
            flash("Invalid username or password", "danger")

    return render_template("login.html")

@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.login"))

@bp.route("/create_admin")
def create_admin():
    existing = User.query.filter_by(username="admin").first()
    if existing:
        return "Admin already exists"

    admin = User(username="admin")
    admin.set_password("admin123")

    db.session.add(admin)
    db.session.commit()

    return "Admin user created successfully!"

@bp.route("/import_csv")
@login_required
def import_csv():
    df = pd.read_csv("healthcare-dataset-stroke-data.csv")
    df = df.fillna(0)

    for _, row in df.iterrows():
        record = StrokeRecord(
            gender=row["gender"],
            age=row["age"],
            hypertension=row["hypertension"],
            heart_disease=row["heart_disease"],
            ever_married=row["ever_married"],
            work_type=row["work_type"],
            Residence_type=row["Residence_type"],
            avg_glucose_level=row["avg_glucose_level"],
            bmi=row["bmi"],
            smoking_status=row["smoking_status"],
            stroke=row["stroke"],
        )
        db.session.add(record)

    db.session.commit()
    return "CSV Imported Successfully!"

@bp.route("/records")
@login_required
def records():
    data = StrokeRecord.query.all()
    return render_template("records.html", data=data)


@bp.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_record(id):
    record = StrokeRecord.query.get_or_404(id)

    if request.method == "POST":
        record.gender = request.form["gender"]
        record.age = request.form["age"]
        record.hypertension = request.form["hypertension"]
        record.heart_disease = request.form["heart_disease"]
        record.ever_married = request.form["ever_married"]
        record.work_type = request.form["work_type"]
        record.Residence_type = request.form["Residence_type"]
        record.avg_glucose_level = request.form["avg_glucose_level"]
        record.bmi = request.form["bmi"]
        record.smoking_status = request.form["smoking_status"]
        record.stroke = request.form["stroke"]

        db.session.commit()
        return redirect(url_for("main.records"))

    return render_template("edit.html", record=record)


@bp.route("/delete/<int:id>")
@login_required
def delete_record(id):
    record = StrokeRecord.query.get_or_404(id)
    db.session.delete(record)
    db.session.commit()
    return redirect(url_for("main.records"))

