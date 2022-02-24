
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
import werkzeug
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user, user_accessed

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exist.')
            return redirect(url_for('register'))
        else:
            hashed_password= generate_password_hash(password,method='pbkdf2:sha256',salt_length=8)
            new_user = User(email=email,password=hashed_password,name=name)
            db.session.add(new_user)
            db.session.commit()
            login_user(user=new_user)
            return render_template('secrets.html',user=new_user)


    return render_template("register.html",logged_in=current_user.is_authenticated)



@app.route('/login',methods=['POST','GET'])
def login():
    
    if request.method == 'POST':
        
        email = request.form['email']
        user =  User.query.filter_by(email=email).first()
        password = request.form['password']
        
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password,password):
            flash('incorrect credentials')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('secrets'))
       
            
    
    return render_template('login.html',logged_in=current_user.is_authenticated)

@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html",user=current_user,logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', filename="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
