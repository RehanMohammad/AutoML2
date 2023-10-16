import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, Blueprint, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from flask_pagedown.fields import PageDownField
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, FileField, PasswordField
from wtforms.validators import DataRequired, InputRequired, Length, ValidationError
import pandas as pd
from supervised.automl import AutoML
import os
import shutil
import hashlib
import bleach
from markdown import markdown
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from flask_bootstrap import Bootstrap
import matplotlib.pyplot as plt





app = Flask(__name__)
bootstrap = Bootstrap(app)

app.config['SECRET_KEY'] = 'mysecretkey'
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['FLASKY_POSTS_PER_PAGE'] = 20
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
app.app_context().push()
db.create_all()
bcrypt = Bcrypt(app)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(64))
    member_since = db.Column(db.DateTime(), default=datetime.datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.datetime.utcnow)
    avatar_hash = db.Column(db.String(32))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    def is_active(self):
       return True
    def __repr__(self):
       return " "  

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    def gravatar_hash(self):
        return hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()

    def gravatar(self, size=100, default='identicon', rating='g'):
        url = 'https://secure.gravatar.com/avatar'
        hash = self.avatar_hash or self.gravatar_hash()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)
 
    def to_json(self):
        json_user = {
            # 'url': url_for('api.get_user', id=self.id),
            'username': self.username,
            'member_since': self.member_since,
            'last_seen': self.last_seen,
            'posts_url': url_for('api.get_user_posts', id=self.id),
            'post_count': self.posts.count()
        }
        return 
    

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))

    def to_json(self):
        json_post = {
            'url': url_for('api.get_post', id=self.id),
            'body': self.body,
            'body_html': self.body_html,
            'timestamp': self.timestamp,
            'author_url': url_for('api.get_user', id=self.author_id),
        }
        return json_post

    @staticmethod
    def from_json(json_post):
        body = json_post.get('body')
        if body is None or body == '':
            raise ValidationError('post does not have a body')
        return Post(body=body)
    
db.event.listen(Post.body, 'set', Post.on_changed_body)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class DataUploadForm(FlaskForm):
    file = FileField('Upload CSV with training data', validators=[DataRequired()])
    # visualize = SubmitField ('Data Visualization')
    x_columns = StringField('Input features (comma-separated)', validators=[DataRequired()])
    y_column = StringField('Target column', validators=[DataRequired()])
    submit = SubmitField('Upload and Proceed')

# class DataUploadForm(FlaskForm):
#     file = FileField('Upload CSV with training data', validators=[DataRequired()])
#     submit = SubmitField('Upload and Proceed')
class SUBMITFORTRAINForm(FlaskForm):
    
    submit = SubmitField('Proceed')


class ModelTrainingForm(FlaskForm):
    x_columns = StringField('Input features (comma-separated)', validators=[DataRequired()])
    y_column = StringField('Target column', validators=[DataRequired()])
    mode = SelectField('AutoML Mode', choices=[('Explain', 'Explain'), ('Perform', 'Perform'), ('Compete', 'Compete')])
    algorithms = StringField('Algorithms (comma-separated)', validators=[DataRequired()])
    time_limit = SelectField('Time limit (seconds)',
                             choices=[('60', '60'), ('120', '120'), ('240', '240'), ('300', '300')])
    submit = SubmitField('Start Training')
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),Email()])
    username = StringField('Username', validators=[DataRequired(), Length(1, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
               'Usernames must have only letters, numbers, dots or '
               'underscores')])
    password = PasswordField('Password', validators=[
        DataRequired(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')
    
# class RegisterForm(FlaskForm):
#     email= StringField(validators=[
#                            InputRequired(), Length(min=12, max=100)], render_kw={"placeholder": "email"})
    

#     password = PasswordField(validators=[
#                              InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

#     submit = SubmitField('Register')
#     def validate_email(self, email):
#         existing_email = User.query.filter_by(
#             email=email.data).first()
#         if existing_email:
#             raise ValidationError('That email already exists. Please choose a different one.')
        
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class SUBMITFORTrainingForm(FlaskForm):
    submit = SubmitField('Proceed')

class PostForm(FlaskForm):
    body = PageDownField("What's on your mind?", validators=[DataRequired()])
    submit = SubmitField('Submit')

class EditProfileForm(FlaskForm):
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    submit = SubmitField('Submit')

class EditProfileAdminForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    username = StringField('Username', validators=[
        DataRequired(), Length(1, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
               'Usernames must have only letters, numbers, dots or '
               'underscores')])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


# @app.route('/home', methods=['GET', 'POST'])
# def home():
#     form = DataUploadForm()
#     if form.validate_on_submit():
#         if not os.path.exists(app.config['UPLOAD_FOLDER']):
#             os.makedirs(app.config['UPLOAD_FOLDER'])

#         filepath = os.path.join(app.config['UPLOAD_FOLDER'], form.file.data.filename)
#         form.file.data.save(filepath)

#         return redirect(url_for('train_model', filepath=filepath))
#     return render_template('home.html', form=form)





@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('home')
            return redirect(next)
        flash('Invalid email or password.')
    # return render_template('auth/login.html')
    return render_template('auth/login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data.lower(),
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('auth/register.html', form=form)

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    form = DataUploadForm()
    if form.validate_on_submit():
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], form.file.data.filename)
        form.file.data.save(filepath)
        x=form.x_columns.data.split(',')
        y=form.y_column.data
        return redirect(url_for('visualize', filepath=filepath,x=x, y=y))
    return render_template('home.html', form=form)

@app.route('/visualize', methods=['GET', 'POST'])
def visualize():
    form = SUBMITFORTrainingForm()
    filepath = request.args.get('filepath')
    xx=request.args.get('x')
    x=request.args.get('x')
    y=request.args.get('y')
    df = pd.read_csv(filepath) 
    plt.scatter(xx, y, data=df) 
    plt.xlabel('X label') 
    plt.ylabel('Y label')      
    plt.show() 
    #put this section on home
    #
    # if not os.path.exists("../static/images"):
    #         os.makedirs("../static/images")
    # # image_path = os.path.join(current_app.config['myapp\static\images'], 'plot.jpg')
    # image_path = "../static/images/plot.png"
    # plt.savefig(os.path.join('../static/images', 'plot.jpg') )
    
    if form.validate_on_submit():         
        return redirect(url_for('train', filepath=filepath))
    return render_template('visualize.html',form=form,tables=[df.head().to_html(classes='data', header="true")])
@app.route('/train', methods=['GET', 'POST'])
def train():    
    filepath = request.args.get('filepath')
    form = ModelTrainingForm()
    if form.validate_on_submit():
        df = pd.read_csv(filepath)
        
        automl = AutoML(mode=form.mode.data, algorithms=form.algorithms.data.split(','),
                        total_time_limit=int(form.time_limit.data))
        automl.fit(df[form.x_columns.data.split(',')], df[form.y_column.data])
        # post.body = automl
        model_path = "./result_model"
        # automl.select_and_save_best()
        post = Post(body=automl.report().data, author=current_user._get_current_object())
        db.session.add(post)
        db.session.commit()
        flash('The Model has been created.')

        # Store results for downloading (if needed)
        # ... (similar to your previous code)
        return render_template('results.html', automl=automl)
    return render_template('train.html', form=form)


@app.route('/index', methods=['GET', 'POST'])
def index():
    form = PostForm()
    if  form.validate_on_submit():
        post = Post(body=form.body.data, author=current_user._get_current_object())
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    
    query = Post.query
    pagination = query.order_by(Post.timestamp.desc()).paginate(
        page=page, per_page=app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('index.html', form=form, posts=posts, pagination=pagination)



@app.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    posts = user.posts.order_by(Post.timestamp.desc()).all()
    return render_template('user.html', user=user, posts=posts)


@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user._get_current_object())
        db.session.commit()
        flash('Your profile has been updated.')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)


@app.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.name = form.name.data
        user.location = form.location.data
        db.session.add(user)
        db.session.commit()
        flash('The profile has been updated.')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    post = Post.query.get_or_404(id)
    if current_user != post.author :
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        db.session.commit()
        flash('The post has been updated.')
        return redirect(url_for('.post', id=post.id))
    form.body.data = post.body
    return render_template('edit_post.html', form=form)
# @app.route('/', methods=['GET', 'POST'])
# def login():
#     form = LoginForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=form.email.data).first()
#         if user:
#             if bcrypt.check_password_hash(user.password, form.password.data):
#                 login_user(user)
#                 return redirect(url_for('home'))

#     return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


# @app.route('/logout', methods=['GET', 'POST'])
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for('login'))


# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     form = RegisterForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=form.email.data).first()
#         if user: # if a user is found, we want to redirect back to register page so user can try again  
#             flash('Email address already exists')
#             return redirect(url_for('login'))
#         hashed_password = bcrypt.generate_password_hash(form.password.data)
#         new_user = User(email=form.email.data, password=hashed_password)
#         db.session.add(new_user)
#         db.session.commit()
#         return redirect(url_for('login'))
#     return render_template('register.html', form= form)
# @app.route('/register')
# def register():
#     return render_template('register.html')

# @app.route('/register', methods=['POST'])
# def register_post():

#     email = request.form.get('email')
#     password = request.form.get('password')

#     user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

#     if user: # if a user is found, we want to redirect back to register page so user can try again  
#         flash('Email address already exists')
#         return redirect(url_for('register'))
#     # create new user with the form data. Hash the password so plaintext version isn't saved.
#     hashed_password = bcrypt.generate_password_hash(password)
#     new_user = User(email=email, password=hashed_password)
#     # add the new user to the database
#     db.session.add(new_user)
#     db.session.commit()
#     return redirect(url_for('login'))
if __name__ == "__main__":
    app.run(debug=True)
