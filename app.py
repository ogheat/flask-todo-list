from flask import Flask, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired
from functools import wraps
from flask import abort
import  datetime
import random
import string




class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign Me In!")


class Taskform(FlaskForm):
    task = StringField("Task", validators=[DataRequired()])
    submit = SubmitField("add task")

class Newlistform(FlaskForm):
    name = StringField("Name of your new task list", validators=[DataRequired()])
    submit = SubmitField("Add")




now = datetime.datetime.now()

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    tasks = relationship("TasksList", back_populates="user")

class TasksList(db.Model):
    __tablename__ = "list"
    id = db.Column(db.Integer, primary_key=True)
    list_name = db.Column(db.String(100))
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    unique_number = db.Column(db.String(100))

    user = relationship("User", back_populates="tasks")
    tasks = relationship("Tasks", back_populates="list")





class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uniq = db.Column(db.Integer, db.ForeignKey("list.unique_number"))
    date = db.Column(db.String(100),default=now.strftime("%d %B"))

    task = db.Column(db.String(100))

    list = relationship("TasksList", back_populates="tasks")




def random_unique():
    strings = ""
    for i in range(8):
        if i % 2 != 0:
            strings += random.choice(string.ascii_letters)
        else:
            strings += str(random.randint(0,9))
    return strings







def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function





@app.route("/")
def home():
    if current_user.is_authenticated:
        id = User.query.filter_by(id=current_user.id).first()
    else:
        id = ""
    return render_template("index.html",current_user=current_user,id=id)


@app.route("/login",methods=["GET","POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # Find user by email entered.
        user = User.query.filter_by(email=email).first()

        # Check stored password hash against entered password hashed.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
            # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
            # Email exists and password correct
        else:
            login_user(user)
            return redirect(url_for('home'))
    if current_user.is_authenticated:
            id = User.query.filter_by(id=current_user.id).first()
    else:
            id = ""
    return render_template("login.html",form=form,current_user=current_user,id=id)
@app.route("/registration",methods=["GET","POST"])
def registration():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            # Send flash messsage
            flash("You've already signed up with that email, log in instead!")
            # Redirect to /login route.
            return redirect(url_for('login'))
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))
    if current_user.is_authenticated:
        id = User.query.filter_by(id=current_user.id).first()
    else:
        id = ""

    return render_template("reg.html",form=form,current_user=current_user,id=id)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))





@app.route("/add-new-list",methods=["GET","POST"])
def add_list():
    if not current_user.is_authenticated:
        return redirect(url_for('home'))
    form = Newlistform()
    if form.validate_on_submit():
        new_list = TasksList (
            list_name = form.name.data,
            author_id = current_user.id,
            unique_number = random_unique()
        )

        db.session.add(new_list)
        db.session.commit()
        return redirect(url_for('lists'))
    if current_user.is_authenticated:
        id = User.query.filter_by(id=current_user.id).first()
    else:
        id = ""

    return render_template("add_list.html",form=form,id=id)


@app.route("/user-area")
def lists():
    if not current_user.is_authenticated:
        return redirect(url_for('home'))
    all_lists = TasksList.query.filter_by(author_id=f"{current_user.id}").all()
    if current_user.is_authenticated:
        id = User.query.filter_by(id=current_user.id).first()
    else:
        id = ""
    return render_template("list.html",current_user=current_user,all=all_lists,id=id)


@app.route("/list/<number>")
def tasks(number):
    if not current_user.is_authenticated:
        return redirect(url_for('home'))
    all_lists = Tasks.query.filter_by(uniq=f"{number}").all()
    if current_user.is_authenticated:
        id = User.query.filter_by(id=current_user.id).first()
    else:
        id = ""
    return render_template("tasks.html",all=all_lists,num=number,id=id)


@app.route("/new_task/<number>",methods=["GET","POST"])
def new_task(number):
    if not current_user.is_authenticated:
        return redirect(url_for('home'))
    global now
    form = Taskform()
    if form.validate_on_submit():
        now = datetime.datetime.now()
        new_task = Tasks(
            uniq=number,
            task=form.task.data,
        )

        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('tasks',number=number))
    if current_user.is_authenticated:
        id = User.query.filter_by(id=current_user.id).first()
    else:
        id = ""

    return render_template("add_task.html",form=form,id=id)


@app.route("/delete-list/int:<number>")
def delete_list(number):
    if not current_user.is_authenticated:
        return redirect(url_for('home'))
    list = TasksList.query.filter_by(unique_number=f"{number}").first()
    db.session.delete(list)
    db.session.commit()
    return redirect(url_for('lists'))

@app.route("/delete-task/int:<number>")
def delete_task(number):
    if not current_user.is_authenticated:
        return redirect(url_for('home'))
    task = Tasks.query.filter_by(id=f"{number}").first()
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('lists'))
















if __name__ == '__main__':
    app.run(debug=True)



