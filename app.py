from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'secret_key'  # Змініть на ваш власний ключ
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Модель користувача
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@app.route('/')
def index():
    return render_template('index.html', logged_in='user_id' in session)

@app.route('/register', methods=['POST'])
def register():
    name = request.form['name']
    email = request.form['email']
    password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

    if User.query.filter_by(email=email).first():
        flash('Ця електронна пошта вже зареєстрована!', 'error')
        return redirect(url_for('auth'))

    new_user = User(name=name, email=email, password=password)
    db.session.add(new_user)
    db.session.commit()
    flash('Реєстрація успішна! Увійдіть до облікового запису.', 'success')
    return redirect(url_for('auth'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        session['user_id'] = user.id
        session['user_name'] = user.name
        flash('Успішний вхід!', 'success')
        return redirect(url_for('profile'))
    else:
        flash('Неправильний email або пароль!', 'error')
        return redirect(url_for('auth'))

@app.route('/auth')
def auth():
    return render_template('auth.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Будь ласка, увійдіть у свій обліковий запис!', 'error')
        return redirect(url_for('auth'))
    return render_template('profile.html', user_name=session['user_name'])

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    flash('Ви вийшли з облікового запису!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    db.create_all()  # Створює таблиці, якщо вони ще не створені
    app.run(debug=True)

#4ota tam
@app.route('/course_tasks')
def course_tasks():
    return render_template('course_tasks.html')



