from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_manager, login_user, login_required, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)  # app.py - файл для запуска
app.secret_key = 'some secret salt'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
manager = LoginManager(app)


class Article(db.Model):
    __tablename__ = 'spots'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    intro = db.Column(db.String(300), nullable=False)
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<Article %r>' % self.id  # выдается запись и id из БД


class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(30), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return '<Users %r>' % self.id  # выдается запись и id из БД


@app.route('/')
@app.route('/home')
def index():
    return render_template("index.html")


@app.route('/about')
def about():
    return render_template("about.html")


@app.route('/stuff')
def stuff():
    return render_template("stuff.html")


@app.route('/auth', methods=['GET', 'POST'])
def auth():
    email = request.form.get('email')
    password = request.form.get('password')

    if email and password:
        user = Users.query.filter_by(email=email).first()
        if check_password_hash(user.passowrd, password):
            login_user(user)

            next_page = request.args.get('next')

            redirect('next_page')
        else:
            flash('Login or password is not correct')
    else:
        flash('Please fill login and password fields')
        return render_template("auth.html")


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return render_template("auth.html")


@app.after_request
def redirect_to_singin(response):
    if response.status_code == 401:
        return redirect(url_for('auth') + '?next=' + request.url)
    return response


@manager.user_loader
def load_user(user_id):
    return Users.get(user_id)


# @app.route('/registration')
# def registration():
#     return render_template("registration.html")


# Просмотр записей в БД
@app.route('/posts')
@login_required
def posts():
    articles = Article.query.order_by(Article.date.desc()).all()  # показ значений из бд сортированных по дате
    return render_template("posts.html", articles=articles)


@app.route('/posts/<int:id>')
@login_required
def post_detail(id):
    article = Article.query.get(id)
    return render_template("posts_detail.html", article=article)


# Удаление из БД
@app.route('/posts/<int:id>/del')
@login_required
def post_delete(id):
    article = Article.query.get_or_404(id)

    try:
        db.session.delete(article)
        db.session.commit()
        return redirect('/posts')
    except:
        return "При добавлении статьи произошла ошибка"


# Изменение записи в БД
@app.route('/posts/<int:id>/update', methods=['POST', 'GET'])
@login_required
def post_update(id):
    article = Article.query.get(id)
    if request.method == "POST":
        article.title = request.form['title']
        article.intro = request.form['intro']
        article.text = request.form['text']

        try:
            db.session.commit()
            return redirect('/posts')
        except:
            return "При добавлении статьи произошла ошибка"
    else:
        return render_template("post_update.html", article=article)


# Запись в БД
@app.route('/create-article', methods=['POST', 'GET'])
@login_required
def create_article():
    if request.method == "POST":
        title = request.form['title']
        intro = request.form['intro']
        text = request.form['text']

        article = Article(title=title, intro=intro, text=text)

        try:
            db.session.add(article)
            db.session.commit()
            return redirect('/posts')
        except:
            return "При добавлении статьи произошла ошибка"
    else:
        return render_template("create-article.html")


@app.route('/registration', methods=['POST', 'GET'])
def create_user():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        password2 = request.form['password2']

        if request.method == 'POST':
            if not (email or password or password2):
                flash('Please, fill all fields!')
            elif password != password2:
                flash('Passwords are not equal!')
            else:
                hash_pwd = generate_password_hash(password)
                new_user = Users(email=email, password=hash_pwd)
                db.session.add(new_user)
                db.session.commit()

                return redirect(url_for('/auth'))

    return render_template("registration.html")


@app.route('/usrs')
@login_required
def usrs():
    usrs = Users.query.all()  # показ значений из бд сортированных по дате
    return render_template("usrs.html", usrs=usrs)


if __name__ == "__main__":  # Проверка что app.py является файлом для запуска
    app.run(debug=True)  # Вывод различных ошибок
