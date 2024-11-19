from token import STRING
from flask import Flask, render_template, request, url_for, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, UserMixin, logout_user, current_user, login_required, LoginManager
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Integer, String, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.fields.simple import PasswordField, SubmitField
from wtforms.validators import DataRequired, Optional
import os
from flask_bootstrap import Bootstrap5
from hashlib import pbkdf2_hmac
from datetime import datetime


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ToDoForm(FlaskForm):
    task = StringField('Task', validators=[DataRequired()])
    date = StringField('Deadline', validators=[Optional()])
    submit = SubmitField('Add Task')

class Base(DeclarativeBase):
  pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)

SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
# initialize the app with the extension
db.init_app(app)

bootstrap = Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(unique=True)
    password: Mapped[str] = mapped_column(String(100))
    lists = relationship("List", back_populates="user")

class List(db.Model):
    __tablename__ = "tasks"
    id: Mapped[int] = mapped_column(primary_key=True)
    task: Mapped[str] = mapped_column(String(100))
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    user = relationship("User", back_populates="lists")

with app.app_context():
    db.create_all()


our_app_iters = 500_000


@app.route("/", methods=['GET', 'POST'])
def home():
    form = ToDoForm()
    user_id = session.get('user_id')  # Get the user ID from the session
    if user_id is None:
        flash("You must be logged in to add a task.")
        return redirect(url_for('login'))  # Redirect to login if not logged in
    else:
        if form.validate_on_submit():
            new_task = List()
            new_task.task = form.task.data
            new_task.date = form.date.data
            new_task.user_id = user_id
            db.session.add(new_task)
            db.session.commit()
            return redirect(url_for("all_tasks"))
    return render_template("index.html", form=form, current_user=current_user)

@app.route("/all", methods= ['GET', 'POST'])
def all_tasks():
    user_id = session.get('user_id')
    result = db.session.execute(db.select(List))
    user_tasks = List.query.filter_by(user_id=user_id).all()
    list_of_tasks = []
    for item in user_tasks:
        list_of_tasks.append(item)
    return render_template('tasks.html', user_tasks=list_of_tasks, tasks=user_tasks, current_user=current_user)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        results = db.session.execute(db.select(User).where(User.email == email ))
        user = results.scalar()

        if not user:
            flash("That email does not exist, please try again.", 'success')
            return redirect(url_for('login'))

        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))

        else:
            login_user(user)
            session['user_id'] = user.id
            return redirect(url_for('home'))
    return render_template("login.html", form=form, current_user=current_user)


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        elif not form.password.data == form.confirm_password.data:
            flash("Password doesn't match, try again")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User()
        new_user.username=form.username.data
        new_user.email=form.email.data
        new_user.password=hashed_password
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('You are successfully registered. Please log in')
        return redirect(url_for("login"))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete(id):
    task = db.get_or_404(List, id)
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for("all_tasks"))


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
