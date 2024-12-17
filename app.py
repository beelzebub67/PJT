import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import logging

app = Flask(__name__)


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///inventory.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False


app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50))


class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    condition = db.Column(db.String(50))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def login():
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])


        if User.query.filter_by(username=username).first():
            flash('Это имя пользователя уже занято. Пожалуйста, выберите другое.')
            return redirect(url_for('register'))

        new_user = User(username=username, password=generate_password_hash(request.form['password']))
        db.session.add(new_user)
        db.session.commit()
        flash('Регистрация успешна!')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/dashboard')
@login_required
def dashboard():
    inventories = Inventory.query.all()
    return render_template('dashboard.html', inventories=inventories)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.errorhandler(500)
def internal_error(error):
    return "500 error: Internal Server Error", 500


@app.errorhandler(404)
def not_found_error(error):
    return "404 error: Not Found", 404


logging.basicConfig(level=logging.DEBUG)


@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Произошла ошибка: {e}")
    return "Произошла ошибка, проверьте логи.", 500

@app.route('/add_inventory', methods=['GET', 'POST'])
@login_required
def add_inventory():
    if request.method == 'POST':
        name = request.form.get('name')
        quantity = request.form.get('quantity')
        condition = request.form.get('condition')

        if name and quantity and condition:
            new_inventory = Inventory(name=name, quantity=quantity, condition=condition)
            db.session.add(new_inventory)
            db.session.commit()
            flash('Товар успешно добавлен!')
        else:
            flash('Пожалуйста, заполните все поля!')
        return redirect(url_for('dashboard'))
    return render_template('add_inventory.html')

@app.route('/delete_inventory/<int:inventory_id>', methods=['POST'])
@login_required
def delete_inventory(inventory_id):
    inventory_item = Inventory.query.get_or_404(inventory_id)
    db.session.delete(inventory_item)
    db.session.commit()
    flash('Товар успешно удален!')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)