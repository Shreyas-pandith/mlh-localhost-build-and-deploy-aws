from flask import Flask, render_template, jsonify, request, abort,redirect, flash, Blueprint, session, url_for
import config
from flask_login import LoginManager
from db import Articles, get_session, database,User
from forms import LoginForm, SignupForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, logout_user, current_user, login_user

login_manager = LoginManager()
application = Flask(__name__)
application.secret_key = 'some secret key'
login_manager.init_app(application)





# Renders UI
@application.route("/")
@login_required
def home():
    session = get_session()
    articles = (
        session.query(Articles,User).filter(Articles.user_id==User.id).all()
    )
    
    return render_template("homepage.html",articles= articles)

@application.route("/new_article",methods=["GET","POST"])
@login_required
def new_article():
    if request.method =="GET":
        return render_template("new_article_page.html")
    if request.method == "POST":
        title=request.form["title"]
        desc=request.form["description"]
        user_id=current_user.id
          
        session = get_session()
        article = Articles(title=title, content=desc,user_id=user_id)
        session.add(article)
        session.commit()
        return redirect("/")



# User Management


@application.route('/login', methods=['GET', 'POST'])
def login_page():
    """User login page."""
    # Bypass Login screen if user is logged in
    if current_user.is_authenticated:
        return redirect("/loggedin")
    login_form = LoginForm(request.form)
    # POST: Create user and redirect them to the app
    if request.method == 'POST':
        if login_form.validate():
            # Get Form Fields
            email = request.form.get('email')
            password = request.form.get('password')
            # Validate Login Attempt
            session = get_session()
            user = session.query(User).filter_by(email=email).first()
            if user:
                if user.check_password(password=password):
                    login_user(user)
                    return redirect('/')
        flash('Invalid username/password combination')
        return redirect('/login')
    # GET: Serve Log-in page
    return render_template('login.html',
                           form=LoginForm(),
                           title='Log in | Flask-Login Tutorial.',
                           template='login-page',
                           body="Log in with your User account.")

@application.route('/loggedin', methods=['GET', 'POST'])
def logedin():
    """User login page."""
    return current_user.name

@application.route('/signup', methods=['GET', 'POST'])
def signup_page():
    """User sign-up page."""
    signup_form = SignupForm(request.form)
    # POST: Sign user in
    if request.method == 'POST':
            if signup_form.validate():
                # Get Form Fields
                name = request.form.get('name')
                email = request.form.get('email')
                password = request.form.get('password')
                session = get_session()
                existing_user=session.query(User).filter_by(email=email).first()
                if existing_user is None:
                    user = User(name=name,
                                email=email,
                                password=generate_password_hash(password, method='sha256'))
                    session.add(user)
                    session.commit()
                    login_user(user)
                    return redirect('/')
                flash('A user already exists with that email address.')
                return redirect('/login')

    # GET: Serve Sign-up page
    return render_template('/signup.html',
                           title='Create an Account | Flask-Login Tutorial.',
                           form=SignupForm(),
                           template='signup-page',
                           body="Sign up for a user account.")


@application.route("/logout")
@login_required
def logout_page():
    """User log-out logic."""
    logout_user()
    return redirect('/login')


@login_manager.user_loader
def load_user(user_id):
    """Check if user is logged-in on every page load."""
    if user_id is not None:
        session = get_session()
        return session.query(User).filter_by(id=user_id).first()
    return None


@login_manager.unauthorized_handler
def unauthorized():
    """Redirect unauthorized users to Login page."""
    flash('You must be logged in to view that page.')
    return redirect('/login')

@application.route('/my_articles')
@login_required
def my_articles():
    session=get_session()
    articles=session.query(Articles).filter_by(user_id=current_user.id).all()
    return render_template("myarticles.html",articles=articles)


if __name__ == "__main__":
    application.run()

