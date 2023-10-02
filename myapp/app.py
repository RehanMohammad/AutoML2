import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, FileField, PasswordField
from wtforms.validators import DataRequired, InputRequired, Length, ValidationError
import pandas as pd
from supervised.automl import AutoML
import os
import shutil

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class DataUploadForm(FlaskForm):
    file = FileField('Upload CSV with training data', validators=[DataRequired()])
    submit = SubmitField('Upload and Proceed')
class ModelTrainingForm(FlaskForm):
    x_columns = StringField('Input features (comma-separated)', validators=[DataRequired()])
    y_column = StringField('Target column', validators=[DataRequired()])
    mode = SelectField('AutoML Mode', choices=[('Explain', 'Explain'), ('Perform', 'Perform'), ('Compete', 'Compete')])
    algorithms = StringField('Algorithms (comma-separated)', validators=[DataRequired()])
    time_limit = SelectField('Time limit (seconds)',
                             choices=[('60', '60'), ('120', '120'), ('240', '240'), ('300', '300')])
    submit = SubmitField('Start Training')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # username = db.Column(db.String(20), nullable=False, unique=True)
    email= db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    data_added= db.column(db.DateTime)
    
with app.app_context():
        db.create_all()
        users = User.query.all()
        print(users)



class RegisterForm(FlaskForm):
    email= StringField(validators=[
                           InputRequired(), Length(min=12, max=100)], render_kw={"placeholder": "email"})
    

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')
    def validate_email(self, email):
        existing_email = User.query.filter_by(
            email=email.data).first()
        if existing_email:
            raise ValidationError(
                'That email already exists. Please choose a different one.')
        
class LoginForm(FlaskForm):
    email = StringField(validators=[
                           InputRequired(), Length(min=12, max=120)], render_kw={"placeholder": "email"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/', methods=['GET', 'POST'])
def home():
    form = DataUploadForm()
    if form.validate_on_submit():
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], form.file.data.filename)
        form.file.data.save(filepath)

        return redirect(url_for('train_model', filepath=filepath))
    return render_template('home.html', form=form)


@app.route('/train', methods=['GET', 'POST'])
def train_model():
    filepath = request.args.get('filepath')
    form = ModelTrainingForm()
    if form.validate_on_submit():
        df = pd.read_csv(filepath)
        automl = AutoML(mode=form.mode.data, algorithms=form.algorithms.data.split(','),
                        total_time_limit=int(form.time_limit.data))
        automl.fit(df[form.x_columns.data.split(',')], df[form.y_column.data])

        # Store results for downloading (if needed)
        # ... (similar to your previous code)

        return render_template('results.html', automl=automl)
    return render_template('train.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))

    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


if __name__ == "__main__":
   

    app.run(debug= True)
