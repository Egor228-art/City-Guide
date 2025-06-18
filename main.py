import hashlib
import re
import os

from werkzeug.utils import secure_filename
from flask_login import LoginManager, current_user
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask import Flask, jsonify, render_template, request, url_for, session
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
admin = Admin(app)
bcrypt = Bcrypt(app)

# Убедитесь, что эти настройки добавлены перед созданием приложения
UPLOAD_FOLDER = os.path.join('static', 'Фотки зданий')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# Создаем папку при запуске
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Определение модели для хранения секретов
class Secret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_name = db.Column(db.String(255), nullable=False, unique=True)
    secret_value = db.Column(db.String(255), nullable=False)

#Работа с фотками и текстом

class Place(db.Model):
    __tablename__ = 'place'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=True)
    telephone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(200), nullable=True)
    image_path = db.Column(db.String(200), nullable=True)
    category = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f'<Place {self.title}>'


# Модели базы данных
class Restaurant(db.Model):
    __tablename__ = 'restaurants'

    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    total_rating = db.Column(db.Float, default=0.0)
    review_count = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Хелпер-функции
def get_client_hash(request):
    ip = request.remote_addr or '127.0.0.1'
    user_agent = request.headers.get('User-Agent', '')
    return hashlib.sha256(f"{ip}_{user_agent}".encode()).hexdigest()

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Функция для создания хэша пользователя
def create_user_hash(request):
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    return hashlib.sha256(f"{ip}_{user_agent}".encode()).hexdigest()

@app.route('/api/reviews', methods=['GET', 'POST'])
def handle_reviews():
    if request.method == 'POST':
        return add_review()
    else:
        restaurant_id = request.args.get('restaurant_id')
        return get_reviews(restaurant_id)

@app.route('/api/reviews/<int:review_id>', methods=['PUT', 'DELETE'])
def handle_single_review(review_id):
    if request.method == 'PUT':
        return update_review(review_id)
    elif request.method == 'DELETE':
        return delete_review(review_id)


@app.route('/api/restaurants/<restaurant_id>', methods=['GET'])
def get_restaurant(restaurant_id):
    try:
        restaurant = db.session.get(Restaurant, restaurant_id)
        if not restaurant:
            # Если ресторана нет, создаем его с базовыми значениями
            restaurant = Restaurant(
                id=restaurant_id,
                name=f"Restaurant {restaurant_id}",
                total_rating=0,
                review_count=0
            )
            db.session.add(restaurant)
            db.session.commit()

        reviews = Review.query.filter_by(restaurant_id=restaurant_id).all()

        return jsonify({
            'restaurant': {
                'id': restaurant.id,
                'name': restaurant.name,
                'rating': float(restaurant.total_rating),
                'review_count': restaurant.review_count
            },
            'reviews': [{
                'id': review.id,
                'user_id': review.user_id,
                'rating': review.rating,
                'comment': review.comment,
                'likes': review.likes,
                'dislikes': review.dislikes,
                'created_at': review.created_at.isoformat(),
                'updated_at': review.updated_at.isoformat() if review.updated_at else None,
                'can_edit': review.can_edit
            } for review in reviews]
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Маршрут для добавления отзыва
# Добавить новый маршрут для получения статистики
@app.route('/api/restaurants/<restaurant_id>/stats', methods=['GET'])
def get_restaurant_stats(restaurant_id):
    reviews = Review.query.filter_by(restaurant_id=restaurant_id).all()

    if not reviews:
        return jsonify({
            'average_rating': 0,
            'total_reviews': 0,
            'ratings': {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        })

    total_reviews = len(reviews)
    average_rating = sum(review.rating for review in reviews) / total_reviews

    # Считаем количество отзывов по каждой оценке
    ratings = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    for review in reviews:
        ratings[review.rating] += 1

    return jsonify({
        'average_rating': average_rating,
        'total_reviews': total_reviews,
        'ratings': ratings
    })

# Обновленный маршрут для добавления отзыва
@app.route('/api/reviews', methods=['POST'])
def add_review():
    data = request.get_json()

    # Валидация данных
    if not data or 'restaurant_id' not in data or 'username' not in data or 'rating' not in data:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        # Создаем новый отзыв
        new_review = Review(
            restaurant_id=data['restaurant_id'],
            username=data['username'],
            rating=data['rating'],
            comment=data.get('comment', '')
        )

        db.session.add(new_review)

        # Обновляем статистику ресторана
        restaurant = Restaurant.query.get(data['restaurant_id'])
        if not restaurant:
            restaurant = Restaurant(
                id=data['restaurant_id'],
                name=f"Restaurant {data['restaurant_id']}",
                total_rating=0,
                review_count=0
            )
            db.session.add(restaurant)

        # Пересчитываем средний рейтинг
        reviews = Review.query.filter_by(restaurant_id=data['restaurant_id']).all()
        total_rating = sum(review.rating for review in reviews)
        review_count = len(reviews)

        restaurant.total_rating = total_rating / review_count if review_count > 0 else 0
        restaurant.review_count = review_count

        db.session.commit()

        return jsonify({
            'message': 'Review added successfully',
            'review': {
                'id': new_review.id,
                'username': new_review.username,
                'rating': new_review.rating,
                'comment': new_review.comment,
                'likes': new_review.likes,
                'dislikes': new_review.dislikes,
                'created_at': new_review.created_at.isoformat()
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# Маршрут для получения отзывов
@app.route('/api/reviews', methods=['GET'])
def get_reviews():
    restaurant_id = request.args.get('restaurant_id')
    if not restaurant_id:
        return jsonify({'error': 'restaurant_id is required'}), 400

    reviews = Review.query.filter_by(restaurant_id=restaurant_id).order_by(Review.created_at.desc()).all()

    return jsonify([{
        'id': review.id,
        'username': review.username,
        'rating': review.rating,
        'comment': review.comment,
        'likes': review.likes,
        'dislikes': review.dislikes,
        'created_at': review.created_at.isoformat()
    } for review in reviews])

@app.route('/api/reviews/<int:review_id>/like', methods=['POST'])
def like_review(review_id):
    try:
        review = Review.query.get_or_404(review_id)
        review.likes += 1
        db.session.commit()
        return jsonify({'likes': review.likes})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/reviews/<int:review_id>/dislike', methods=['POST'])
def dislike_review(review_id):
    try:
        review = Review.query.get_or_404(review_id)
        review.dislikes += 1
        db.session.commit()
        return jsonify({'dislikes': review.dislikes})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/reviews/<int:review_id>', methods=['PUT'])
def update_review(review_id):
    data = request.get_json()
    review = Review.query.get_or_404(review_id)

    # Проверяем токен редактирования (для анонимных) или права пользователя
    edit_token = data.get('edit_token')
    if not review.can_edit(edit_token):
        return jsonify({'message': 'You cannot edit this review'}), 403

    try:
        old_rating = review.rating

        # Обновляем данные отзыва
        if 'rating' in data:
            review.rating = data['rating']
        if 'comment' in data:
            review.comment = data['comment']

        review.updated_at = datetime.utcnow()

        # Обновляем статистику ресторана, если изменился рейтинг
        if 'rating' in data:
            restaurant = Restaurant.query.get(review.restaurant_id)
            if restaurant:
                # Пересчитываем общий рейтинг
                total = (restaurant.total_rating * restaurant.review_count) - old_rating + data['rating']
                restaurant.total_rating = total / restaurant.review_count
                restaurant.last_updated = datetime.utcnow()

        db.session.commit()

        return jsonify({
            'message': 'Review updated successfully',
            'review': {
                'id': review.id,
                'rating': review.rating,
                'comment': review.comment,
                'updated_at': review.updated_at.isoformat(),
                'can_edit': review.can_edit(edit_token)
            },
            'restaurant': {
                'rating': restaurant.total_rating if restaurant else None
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/api/reviews/<int:review_id>', methods=['DELETE'])
def delete_review(review_id):
    review = Review.query.get(review_id)
    if not review:
        return jsonify({'message': 'Review not found'}), 404

    try:
        restaurant = Restaurant.query.get(review.restaurant_id)

        # Удаляем отзыв
        db.session.delete(review)

        # Обновляем статистику ресторана
        if restaurant and restaurant.review_count > 0:
            if restaurant.review_count == 1:
                restaurant.total_rating = 0
            else:
                total = (restaurant.total_rating * restaurant.review_count) - review.rating
                restaurant.total_rating = total / (restaurant.review_count - 1)

            restaurant.review_count -= 1
            restaurant.last_updated = datetime.utcnow()

        db.session.commit()

        return jsonify({
            'message': 'Review deleted successfully',
            'restaurant': {
                'rating': restaurant.total_rating if restaurant else None,
                'review_count': restaurant.review_count if restaurant else None
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500


@app.route('/add_place', methods=['GET', 'POST'])
def add_place():
    categories = ['Ресторан', 'Кафе', 'Магазин', 'Музей', 'Театр', 'Библиотека',
                  'Парк', 'Кинотеатр', 'Спортплощадка', 'Церковь', 'Гостиница', 'Иконка']

    if request.method == 'POST':
        try:
            # Получаем данные из формы
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            telephone = request.form.get('telephone', '').strip()
            address = request.form.get('address', '').strip()
            category = request.form.get('category', '').strip()

            if not category:
                return 'Категория обязательна для заполнения', 400

            # Обработка файла
            image_path = None
            if 'image' in request.files:
                file = request.files['image']
                if file.filename != '':
                    if not allowed_file(file.filename):
                        return 'Недопустимый тип файла', 400

                    filename = secure_filename(file.filename)
                    if not filename:
                        return 'Недопустимое имя файла', 400

                    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    try:
                        file.save(save_path)
                        image_path = 'Фотки зданий/' + filename
                    except Exception as e:
                        app.logger.error(f'Ошибка сохранения файла: {str(e)}')
                        return 'Ошибка при сохранении файла', 500

            # Создаем новую запись
            new_place = Place(
                title=title or None,
                description=description or None,
                telephone=telephone or None,
                address=address or None,
                image_path=image_path,
                category=category
            )

            db.session.add(new_place)
            db.session.commit()

            return 'Место успешно добавлено!'

        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Ошибка при добавлении места: {str(e)}')
            return f'Внутренняя ошибка сервера: {str(e)}', 500

    # GET запрос
    return render_template('add_place.html', categories=categories)

@app.route('/places')
def places():
    places = Place.query.all()
    return render_template('places.html', places=places)

# Создание таблицы в базе данных
with app.app_context():
    db.create_all()

# Функция для добавления секрета в базу данных
def add_secret(key_name, secret_value):
    with app.app_context():
        existing_secret = Secret.query.filter_by(key_name=key_name).first()
        if existing_secret:
            return
        new_secret = Secret(key_name=key_name, secret_value=secret_value)
        db.session.add(new_secret)
        db.session.commit()

# Функция для получения секрета из базы данных
def get_secret(key_name):
    with app.app_context():
        secret = Secret.query.filter_by(key_name=key_name).first()
        return secret.secret_value if secret else None

# Получение секретного ключа из базы данных и настройка Flask-приложения
app.config['SECRET_KEY'] = get_secret('SECRET_KEY')

# Определяем модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

with app.app_context():
    db.create_all()

def register_user(username, password, secret_key):
    try:
        if secret_key != app.config['SECRET_KEY']:
            return False, "Неверный секретный ключ."

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return False, "Пользователь с таким логином уже существует."

        # Хеширование пароля
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return True, "Пользователь успешно зарегистрирован."

    except Exception as e:
        return False, str(e)

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    secret_key = request.form['secret_key']

    success, message = register_user(username, password, secret_key)
    if success:
        session['username'] = username
        return jsonify({'success': True, 'username': username})
    else:
        return jsonify({'success': False, 'message': message})

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        session['username'] = username
        return jsonify({'success': True, 'username': username})
    else:
        return jsonify({'success': False, 'message': 'Неверный логин или пароль'})

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify({'success': True})

# Список элементов для поиска
restaurants = [
    #Рестораны и Кафе
    {
        "name": "Барашки",
        "description": "Ресторан «Барашки» предлагает своим гостям блюда грузинской кухни, приготовленные по традиционным рецептам.",
        "image": "Фотки зданий/Барашки.png",
        "contact": "+7 (8162) 55-53-22",
        "tegs": "ресторан кафе",
        "contact2": "ул. Ломоносова, 22/2, Великий Новгород"
    },{
        "name": "Гурметто",
        "description": "Ресторан «Гурметто» — это место, где вы можете насладиться изысканной европейской кухней и уютной атмосферой. Здесь вы найдете широкий выбор блюд, включая суши, роллы, пиццу, супы, стейки и многое другое.",
        "image": "Фотки зданий/Гурметто.png",
        "contact": "+7 (8162) 92-64-94",
        "tegs": "ресторан",
        "contact2": "ул. Ломоносова, 37, Великий Новгород"
    },{
        "name": "ПиццаФабрика",
        "description": "Ресторан «ПиццаФабрика» — это идеальное место для семейного отдыха.",
        "image": "Фотки зданий/ПиццаФабрика.png",
        "contact": "8 (800) 550-06-00",
        "tegs": "ресторан пиццерия",
        "contact2": "Большая Санкт-Петербургская ул., 39, корп. 22"
    },{
        "name": "Brewmen",
        "description": "Ресторан Brewmen — это место, где вы можете попробовать крафтовое пиво собственного производства, а также настойки и наливки.",
        "image": "Фотки зданий/Brewmen.png",
        "contact": "+7 (8162) 92-00-00",
        "tegs": "ресторан бар паб",
        "contact2": "Большая Санкт-Петербургская ул., 64"
    },{
        "name": "Иль-де-Франс",
        "description": "Ресторан «Иль-де-Франс» — это место, где можно провести любое мероприятие, будь то свадьба, юбилей или корпоратив.",
        "image": "Фотки зданий/Иль-де-Франс.png",
        "contact": "+7 (8162) 33-20-57",
        "tegs": "ресторан банкетный зал бар паб",
        "contact2": "Великая ул., 22, стр. 5"
    },{
        "name": "Пряник",
        "description": "Ресторан «Пряник» — это место, где вы можете насладиться вкусной едой и отдохнуть после активного дня. Интерьер ресторана создает атмосферу домашнего уюта: теплый свет, деревянная мебель и мягкие диваны погружают в расслабляющую обстановку.",
        "image": "Фотки зданий/Пряник.png",
        "contact": "+7 (911) 041-37-24",
        "tegs": "ресторан бар паб",
        "contact2": "Большая Санкт-Петербургская ул., 23"
    },{
        "name": "Marusya",
        "description": "Ресторан Marusya — это стильное и современное место, где можно попробовать аутентичные блюда русской кухни, а также блюда других кухонь, такие как паста и тартары.",
        "image": "Фотки зданий/Marusya.png",
        "contact": "+7 (8162) 78-88-87",
        "tegs": "ресторан доставка еды и обедов кафе",
        "contact2": "Предтеченская ул., 24, район Софийская сторона Район Софийская сторона, этаж 1",
    },{
        "name": "Проун",
        "description": "Ресторан «Проун» предлагает своим гостям блюда русской авангардной кухни, приготовленные с творческим подходом. В меню можно найти такие блюда, как борщ с необычной подачей и оригинальными ингредиентами, стейк из оленины, утиная грудка и тартар из говядины.",
        "image": "Фотки зданий/Проун.png",
        "contact": "+7 (8162) 50-07-70",
        "tegs": "ресторан кофейня бар паб",
        "contact2": "Предтеченская ул., 24, район Софийская сторона 5"
    },{
        "name": "ПхалиХинкали",
        "description": "Ресторан «ПхалиХинкали» предлагает своим гостям блюда грузинской кухни, приготовленные по традиционным рецептам.",
        "image": "Фотки зданий/ПхалиХинкали.png",
        "contact": "+7 (8162) 90-46-46",
        "tegs": "ресторан кафе",
        "contact2": "Людогоща ул., 10, район Софийская сторона"
    },{
        "name": "Мамонт",
        "description": "Ресторан «Мамонт» — это место, где вы можете насладиться вкусной едой и уютной атмосферой. Интерьер ресторана выполнен в фирменном стиле, который напоминает пещеру.",
        "image": "Фотки зданий/Мамонт.png",
        "contact": "+7 (8162) 68-11-09",
        "tegs": "ресторан",
        "contact2": "ул. Газон, 7/1, район Софийская сторона"
    },{
        "name": "География",
        "description": "Ресторан «География» расположен в самом сердце Великого Новгорода, в окружении главных достопримечательностей, с видом на Кремль и фонтан «Садко». В ресторане есть два зала: внутри помещения и закрытая веранда, а также бесплатная парковка для посетителей.",
        "image": "Фотки зданий/География.png",
        "contact": "+7 (8162) 90-00-55",
        "tegs": "ресторан кофейня кондитерская кафе пекарня",
        "contact2": "ул. Газон, 2, район Софийская сторона"
    },{
        "name": "Токио-City",
        "description": "Ресторан «Токио-City» — это современный проект с универсальной кухней.",
        "image": "Фотки зданий/Токио-City.png",
        "contact": "+7 (8162) 55-52-72",
        "tegs": "ресторан кальян-бар пиццерия",
        "contact2": "Людогоща ул., 2, Софийская сторона"
    },{
        "name": "Чародейка",
        "description": "Ресторан «Чародейка» — это место, куда хочется возвращаться. Здесь стильно, вкусно и по-домашнему уютно. Официанты и персонал молодцы. Кухня прекрасна, бургер — шедевр.",
        "image": "Фотки зданий/Чародейка.png",
        "contact": "+7 (911) 600-14-09",
        "tegs": "ресторан магазин продуктов кафе бар паб",
        "contact2": "Чудинцева ул., 1/1, район Софийская сторона"
    },{
        "name": "Napoli",
        "description": "Каждый гость найдет в меню ресторана блюдо на свой вкус. Понятная и известная, легкая и современная, но в то же время тонкая и изысканная кухня средиземноморья.",
        "image": "Фотки зданий/Napoli.png",
        "contact": "+7 (911) 600-30-95",
        "tegs": "ресторан кафе",
        "contact2": "Студенческая ул., 21/43, Донецкий район Первый"
    },{
        "name": "Юрьевское Подворье",
        "description": "Ресторан «Юрьевское Подворье» предлагает своим гостям аутентичную русскую кухню, приготовленную из традиционных продуктов.",
        "image": "Фотки зданий/Юрьевское Подворье.png",
        "contact": "+7 (8162) 78-80-08",
        "tegs": "ресторан банкетный зал кафе",
        "contact2": "Юрьевское ш., 6А Район Юрьево, этаж 1"
    },{
        "name": "Legenda",
        "description": "Ресторан «Legenda» — это место, где можно вкусно поесть и весело потанцевать. После 20:00 работает диджей, который включает музыку по желанию гостей.",
        "image": "Фотки зданий/Legenda.png",
        "contact": "+7 (8162) 66-07-96",
        "tegs": "ресторан кафе",
        "contact2": "Михайлова ул., 3, корп. 4, район Торговая сторона, Великий Новгород этаж 1"
    },{
        "name": "Сытый гусь",
        "description": "Ресторан «Сытый гусь» расположен в Великом Новгороде, рядом с музеем деревянного зодчества «Витославицы». Интерьер ресторана выполнен в старинном стиле, с использованием дерева и ткани, а в центре зала расположена настоящая русская печь.",
        "image": "Фотки зданий/Сытый гусь.png",
        "contact": "+7 (8162) 90-98-98",
        "tegs": "ресторан",
        "contact2": "Юрьевское ш., 15А музей Витославлицы"
    },{
        "name": "Дом Берга",
        "description": "«Дом Берга» — это ресторан русской кухни, расположенный в историческом здании купца Берга в Великом Новгороде. Интерьер ресторана выполнен в смешанной стилистике, сочетающей мотивы русской сказки, дворянства и современности.",
        "image": "Фотки зданий/Дом Берга.png",
        "contact": "+7 (8162) 78-88-38",
        "tegs": "ресторан",
        "contact2": "Большая Московская ул., 24 • этаж 1"
    },{
        "name": "Рестобар Кружечный Двор",
        "description": "Рестобар «Кружечный Двор» — это атмосферное место с низкими сводчатыми кирпичными потолками, картинами с мишками, бочками, вениками, уткой-графином, дровником и росписью на стенах.",
        "image": "Фотки зданий/Рестобар Кружечный Двор.png",
        "contact": "+7 (921) 606-53-53",
        "tegs": "ресторан кафе бар паб",
        "contact2": "ул. Рогатица, 14, район Торговая сторона, Великий Новгород этаж цокольный"
    },{
        "name": "Bistro Palazzo 5",
        "description": "Ресторан Bistro Palazzo 5 расположен в историческом центре Великого Новгорода, на Торговой стороне. Интерьер ресторана выполнен в строгом немецко-скандинавском стиле, с большой летней террасой, оформленной в цветах и с видом на красивый сад.",
        "image": "Фотки зданий/Bistro Palazzo 5.png",
        "contact": "+7 (8162) 60-88-86",
        "tegs": "ресторан суши-бар пиццерия",
        "contact2": "Дворцовая ул., 5, район Торговая сторона"
    },{
        "name": "Фрегат Флагман",
        "description": "Ресторан «Фрегат Флагман» расположен на борту пришвартованного фрегата, откуда открывается потрясающий вид на реку Волхов и Новгородский Кремль.",
        "image": "Фотки зданий/Фрегат Флагман.png",
        "contact": "+7 (8162) 50-07-77",
        "tegs": "ресторан банкетный зал ночной клуб",
        "contact2": "наб. Александра Невского, 22/1, район Торговая сторона"
    },{
        "name": "Русская душа",
        "description": "Ресторан «Русская душа» расположен на берегу реки Волхов, откуда открывается прекрасный вид на Новгородский кремль. Интерьер ресторана выполнен в светлых тонах, что создает уютную атмосферу.",
        "image": "Фотки зданий/Русская душа.png",
        "contact": "+7 (8162) 50-07-77",
        "tegs": "ресторан",
        "contact2": "наб. Александра Невского, 22/1, район Торговая сторона этаж 2"
    },{
        "name": "Сказка",
        "description": "Ресторан «Сказка» — это место, где вы можете попробовать блюда разных кухонь, такие как восточная, кавказская, итальянская и азиатская.",
        "image": "Фотки зданий/Сказка.png",
        "contact": "+7 (8162) 28-03-41",
        "tegs": "ресторан доставка еды и обедов кафе",
        "contact2": "ул. Мерецкова-Волосова, 11, Софийская сторона, Великий Новгород"
    },{
        "name": "Чайхана Сказка",
        "description": "«Чайхана Сказка» — это ресторан, расположенный на набережной реки Волхов в Великом Новгороде. Он предлагает своим гостям широкий выбор блюд, включая манты, хинкали, шашлыки, плов, хачапури, роллы и пиццу.",
        "image": "Фотки зданий/Чайхана Сказка.png",
        "contact": "+7 (8162) 50-01-11",
        "tegs": "ресторан доставка еды и обедов кафе",
        "contact2": "наб. Александра Невского, 26, район Торговая сторона, Великий Новгород"
    },{
        "name": "Наffига козе баян?!",
        "description": "Ресторан «Наffига козе баян?!» — это место, где стиль, креатив и фантазия сочетаются с кулинарной идеей.",
        "image": "Фотки зданий/Наffига козе баян.png",
        "contact": "+7 (911) 633-10-27",
        "tegs": "ресторан кафе бар паб",
        "contact2": "Великая ул., 3, Софийская сторона, Великий Новгород"
    },{
        "name": "HURMA",
        "description": "Ресторан «HURMA» — Нет описания.",
        "image": "Фотки зданий/Хурма.png",
        "contact": "+7 (8162) 90-08-90",
        "tegs": "ресторан банкетный зал бар паб",
        "contact2": "Великая ул., 16, стр. 1, Великий Новгород"
    },{
        "name": "My Kitchen",
        "description": "My Kitchen — это ресторан, который предлагает своим гостям блюда грузинской, европейской и японской кухни. В меню можно найти такие блюда, как хачапури, сациви, томатный суп, борщ и другие.",
        "image": "Фотки зданий/My Kitchen.png",
        "contact": "+7 (8162) 90-07-20",
        "tegs": "ресторан пиццерия кафе бар паб",
        "contact2": "Большая Московская ул., 52/9, Великий Новгород"
    },{
        "name": "Фазенда",
        "description": "Ресторан «Фазенда» предлагает своим гостям разнообразное меню, включающее в себя блюда европейской и японской кухни, а также завтраки.",
        "image": "Фотки зданий/Фазенда.png",
        "contact": "+7 (8162) 60-88-83",
        "tegs": "ресторан суши-бар пиццерия",
        "contact2": "Большая Санкт-Петербургская ул., 21, Великий Новгород этаж 1",
    },{
        "name": "Mbur",
        "description": "Mbur — это ресторан, бар, паб и кейтеринг, расположенный в Великом Новгороде. Он предлагает своим гостям разнообразное меню, включая бизнес-ланчи, а также возможность проведения банкетов и других мероприятий.",
        "image": "Фотки зданий/Mbur.png",
        "contact": "+7 (8162) 73-05-99",
        "tegs": "ресторан кейтеринг бар паб",
        "contact2": "Новолучанская ул., 14"
    },{
        "name": "На Солнце",
        "description": "Ресторан «На Солнце» расположен в отеле «Береста Парк», что делает его идеальным местом для тех, кто проживает в отеле.",
        "image": "Фотки зданий/На Солнце.png",
        "contact": "+7 (8162) 90-60-60",
        "tegs": "ресторан",
        "contact2": "Студенческая ул., 2, Донецкий район"
    },{
        "name": "Шаурpoint",
        "description": "ШАУРPOINT-cеть ресторанов быстрого питания в разных форматах – от ресторанов в собственных зданиях и точек быстрого обслуживания до фуд-траков.",
        "image": "Фотки зданий/Шаурpoint.png",
        "contact": "+7 (996) 569-41-19",
        "tegs": "Быстрое питание кафе ресторан",
        "contact2": "ул. Державина, 19"
    },{
        "name": "Дорадо",
        "description": "Ресторан «Дорадо» предлагает своим гостям широкий выбор суши и роллов, а также пиццу и лапшу вок.",
        "image": "Фотки зданий/Дорадо.png",
        "contact": "+7 (963) 368-99-68",
        "tegs": "ресторан пиццерия",
        "contact2": "Большая Московская ул., 120А • этаж 2"
    },{
        "name": "Садко",
        "description": "Ресторан «Садко» — это место, где можно вкусно и сытно позавтракать, пообедать или поужинать.",
        "image": "Фотки зданий/Садко.png",
        "contact": "+7 (8162) 66-18-08",
        "tegs": "ресторан кафе",
        "contact2": "ул. Фёдоровский Ручей, 16, район Торговая сторона"
    },{
        "name": "Лимузин",
        "description": "Ресторан «Лимузин» — Нет описания.",
        "image": "Фотки зданий/Лимузин.png",
        "contact": "+7 (951) 726-32-32",
        "tegs": "банкетный зал ресторан пиццерия",
        "contact2": "Студенческая ул., 31, Донецкий район этаж 2"
    },{
        "name": "Персона",
        "description": "Банкетный зал «Персона» — это место, где можно провести любое мероприятие, будь то свадьба, корпоратив или выпускной вечер.",
        "image": "Фотки зданий/Персона.png",
        "contact": "+7 (911) 600-20-19",
        "tegs": "банкетный зал ресторан кафе",
        "contact2": "Батецкая ул., 22, Псковский район этаж 3"
    },{
        "name": "Бруклин",
        "description": "«Бруклин» — это заведение быстрого питания, где вы можете насладиться вкусными и сытными блюдами, такими как бургеры, хот-доги, шаурма и картофель фри.",
        "image": "Фотки зданий/Бруклин.png",
        "contact": "+7 (953) 907-00-88",
        "tegs": "быстрое питание ресторан кафе",
        "contact2": "Чудинцева ул., 7, район Софийская сторона"
    },{
        "name": "Изюм",
        "description": "Найди свою «Изюминку» и живи со вкусом!",
        "image": "Фотки зданий/Изюм.png",
        "contact": "+7 (8162) 90-08-82",
        "tegs": "Кафе доставка еды и обедов ресторан",
        "contact2": "Молотковская ул., 4, район Торговая сторона"
    },{
        "name": "Хлебник",
        "description": "Кафе «Хлебник» — это уютное место, где можно позавтракать, пообедать или просто перекусить.",
        "image": "Фотки зданий/Хлебник.png",
        "contact": "+7 (995) 233-31-22",
        "tegs": "Кафе кофейня пекарня",
        "contact2": "ул. Фёдоровский Ручей, 2/13, район Торговая сторона"
    },{
        "name": "Время Ч",
        "description": "Кафе «Время Ч» — это место, где вы можете насладиться разнообразным меню, включающим в себя авторские блюда и классические рецепты. Интерьер кафе стильно оформлен и создает приятный фон для вечера, а спокойная музыка дополняет общую атмосферу.",
        "image": "Фотки зданий/Время Ч.png",
        "contact": "+7 (8162) 99-80-40",
        "tegs": "Кафе ресторан бар паб",
        "contact2": "Щитная ул., 7/31, район Торговая сторона"
    },{
        "name": "МамаСушиПицца",
        "description": "Кафе «МамаСушиПицца» — Нет описания.",
        "image": "Фотки зданий/МамаСушиПицца.png",
        "contact": "+7 (991) 493-10-09",
        "tegs": "Кафе суши-бар пиццерия",
        "contact2": "ул. Ломоносова, 43"
    },{
        "name": "Ромитто",
        "description": "«Ромитто» — это заведение быстрого питания, где можно попробовать разнообразные блюда, такие как шаурма, гамбургеры, пельмени, лапша и корн-доги.",
        "image": "Фотки зданий/Ромитто.png",
        "contact": "+7 (8162) 70-06-00",
        "tegs": "Быстрое питание доставка еды и обедов кафе",
        "contact2": "ул. Ломоносова, 37"
    },{
        "name": "Колобок",
        "description": "Кафе «Колобок» — это место, где можно вкусно и недорого поесть.",
        "image": "Фотки зданий/Колобок.png",
        "contact": "+7 (8162) 63-82-04",
        "tegs": "Кафе столовая быстрое питание",
        "contact2": "Большая Московская ул., 28"
    },{
        "name": "Старик Хинкалыч",
        "description": "«Старик Хинкалыч» — это кафе грузинской кухни, где вы можете попробовать различные виды хинкали, такие как хинкали с говядиной, сыром, картофелем и грибами, а также хачапури по-аджарски.",
        "image": "Фотки зданий/Старик Хинкалыч.png",
        "contact": "+7‒905‒290‒87‒98",
        "tegs": "Кафе ресторан",
        "contact2": "район Софийская сторона, Розважа ул., 13"
    },{
        "name": "Тепло траттория",
        "description": "Кафе «Тепло траттория» — это уютное заведение с милым интерьером, где много света и зелени. Гостям нравится мясная пицца, сырные палочки, салат с форелью, лимонный чизкейк, пицца и котлеты «Пожарские».",
        "image": "Фотки зданий/Тепло траттория.png",
        "contact": "+7 (8162) 90-98-62",
        "tegs": "Ресторан пиццерия кафе",
        "contact2": "Прусская ул., 1/7, Великий Новгород"
    },{
        "name": "Шкипер",
        "description": "Кафе «Шкипер» Настоящая кавказская кухня в приятном месте города!",
        "image": "Фотки зданий/Шкипер.png",
        "contact": "+7 (8162) 63-39-80",
        "tegs": "Кафе ресторан",
        "contact2": "Студенческая ул., 4, Донецкий район"
    },{
        "name": "Диез",
        "description": "Кафе «Диез» — это место, где можно вкусно и недорого поесть. Формат обслуживания — столовая, но антураж как в кафе. Из окон открывается красивый вид на набережную Волхова.",
        "image": "Фотки зданий/Диез.png",
        "contact": "+7 (8162) 69-30-82",
        "tegs": "Кафе",
        "contact2": "ул. Фёдоровский Ручей, 2/13, район Торговая сторона этаж 1"
    },{
        "name": "Cafe Le Chocolat",
        "description": "Кафе «Диез» — это место, где можно вкусно и недорого поесть. Формат обслуживания — столовая, но антураж как в кафе. Из окон открывается красивый вид на набережную Волхова.",
        "image": "Фотки зданий/Cafe Le Chocolat.png",
        "contact": "+7 (8162) 69-30-82",
        "tegs": "Кафе ресторан",
        "contact2": "ул. Фёдоровский Ручей, 2/13, район Торговая сторона этаж 1"
    },
    #Магазины
    {
        "name": "Гипер Лента",
        "description": "«Гипер Лента» — российская сеть гипермаркетов с широким ассортиментом товаров: продукты, бытовая химия, электроника. Предлагает акции, скидки и программы лояльности для удобного шопинга.",
        "image": "Фотки зданий/Гипер Лента.png",
        "contact": "8 (800) 700-41-11",
        "tegs": "Продуктовый гипермаркет",
        "contact2": "Великая ул., 22А, Великий Новгород"
    },{
        "name": "ВкусВилл",
        "description": "«ВкусВилл» — российская сеть магазинов, специализирующаяся на продаже натуральных продуктов питания и товаров для здоровья.",
        "image": "Фотки зданий/ВкусВилл.png",
        "contact": "8 (800) 550-86-02",
        "tegs": "Супермаркет магазин продуктов",
        "contact2": "Псковская ул., 32"
    },{
        "name": "Дикси",
        "description": "«Дикси» — российская сеть супермаркетов, предлагающая разнообразие продуктов питания, бытовых товаров и товаров для дома. Сеть известна своими доступными ценами и регулярными акциями для покупателей.",
        "image": "Фотки зданий/Дикси.png",
        "contact": "8 (800) 550-86-02",
        "tegs": "Магазин продуктов супермаркет",
        "contact2": "Псковская ул., 32"
    },{
        "name": "Дикси",
        "description": "«Дикси» — российская сеть супермаркетов, предлагающая разнообразие продуктов питания, бытовых товаров и товаров для дома. Сеть известна своими доступными ценами и регулярными акциями для покупателей.",
        "image": "Фотки зданий/Дикси1.png",
        "contact": "8 (800) 101-10-01",
        "tegs": "Магазин продуктов супермаркет",
        "contact2": "ул. Ломоносова, 8/1"
    },{
        "name": "Дикси",
        "description": "«Дикси» — российская сеть супермаркетов, предлагающая разнообразие продуктов питания, бытовых товаров и товаров для дома. Сеть известна своими доступными ценами и регулярными акциями для покупателей.",
        "image": "Фотки зданий/Дикси2.png",
        "contact": "8 (800) 101-10-01",
        "tegs": "Магазин продуктов супермаркет",
        "contact2": "просп. Мира, 40, корп. 1, Западный район"
    },{
        "name": "Перекрёсток",
        "description": "«Перекрёсток» — российская сеть супермаркетов, предлагающая широкий ассортимент продуктов питания, напитков и товаров для дома. Сеть известна высоким качеством товаров, удобным расположением магазинов и программами лояльности для постоянных клиентов.",
        "image": "Фотки зданий/Перекрёсток.png",
        "contact": "8 (800) 200-95-55",
        "tegs": "Магазин продуктов супермаркет",
        "contact2": "ул. Ломоносова, 29 • ТЦ Мармелад"
    },{
        "name": "Магнит",
        "description": "«Магнит» — крупная российская розничная сеть, предлагающая разнообразные продукты питания и товары для дома. Известен доступными ценами, акциями и программами лояльности. Сеть включает супермаркеты и магазины формата <у дома>.",
        "image": "Фотки зданий/Магнит.png",
        "contact": "8 (800) 200-90-02",
        "tegs": "Магазин продуктов супермаркет",
        "contact2": "ул. Фёдоровский Ручей, 2Г, район Торговая сторона этаж 1"
    },{
        "name": "Магнит",
        "description": "«Магнит» — крупная российская розничная сеть, предлагающая разнообразные продукты питания и товары для дома. Известен доступными ценами, акциями и программами лояльности. Сеть включает супермаркеты и магазины формата <у дома>.",
        "image": "Фотки зданий/Магнит1.png",
        "contact": "8 (800) 200-90-02",
        "tegs": "Магазин продуктов супермаркет",
        "contact2": "ул. Мерецкова-Волосова, 7/1, район Софийская сторона"
    },{
        "name": "Магнит",
        "description": "«Магнит» — крупная российская розничная сеть, предлагающая разнообразные продукты питания и товары для дома. Известен доступными ценами, акциями и программами лояльности. Сеть включает супермаркеты и магазины формата <у дома>.",
        "image": "Фотки зданий/Магнит2.png",
        "contact": "8 (800) 200-90-02",
        "tegs": "Магазин продуктов супермаркет",
        "contact2": "Батецкая ул., 22, Псковский район"
    },{
        "name": "Пятёрочка",
        "description": "«Пятёрочка» — российская сеть магазинов формата <у дома>, предлагающая доступные продукты питания и товары повседневного спроса. Известна акциями и удобным расположением, что делает покупки быстрыми и комфортными.",
        "image": "Фотки зданий/Пятёрочка.png",
        "contact": "8 (800) 555-55-05",
        "tegs": "супермаркет",
        "contact2": "Воскресенский бул., 4, Привокзальный район"
    },{
        "name": "Пятёрочка",
        "description": "«Пятёрочка» — российская сеть магазинов формата <у дома>, предлагающая доступные продукты питания и товары повседневного спроса. Известна акциями и удобным расположением, что делает покупки быстрыми и комфортными.",
        "image": "Фотки зданий/Пятёрочка1.png",
        "contact": "8 (800) 555-55-05",
        "tegs": "супермаркет",
        "contact2": "Воскресенский бул., 4, Привокзальный район"
    },{
        "name": "Осень",
        "description": "«Осень» — российская сеть магазинов формата <у дома>, предлагающая широкий ассортимент доступных продуктов и товаров повседневного спроса. Она известна удобным расположением, частыми акциями и низкими ценами, что делает её популярной среди покупателей.",
        "image": "Фотки зданий/Осень.png",
        "contact": "+7 (8162) 68-50-50",
        "tegs": "супермаркет Магазин продуктов",
        "contact2": "Большая Санкт-Петербургская ул., 19"
    },{
        "name": "Осень",
        "description": "«Осень» — российская сеть магазинов формата <у дома>, предлагающая широкий ассортимент доступных продуктов и товаров повседневного спроса. Она известна удобным расположением, частыми акциями и низкими ценами, что делает её популярной среди покупателей.",
        "image": "Фотки зданий/Осень1.png",
        "contact": "+7 (8162) 68-50-50",
        "tegs": "супермаркет Магазин продуктов",
        "contact2": "Шелонская ул., 30, Псковский район"
    },{
        "name": "Осень",
        "description": "«Осень» — российская сеть магазинов формата <у дома>, предлагающая широкий ассортимент доступных продуктов и товаров повседневного спроса. Она известна удобным расположением, частыми акциями и низкими ценами, что делает её популярной среди покупателей.",
        "image": "Фотки зданий/Осень2.png",
        "contact": "+7 (8162) 68-50-50",
        "tegs": "супермаркет Магазин продуктов",
        "contact2": "ул. Зелинского, 21"
    },{
        "name": "Осень",
        "description": "«Осень» — российская сеть магазинов формата <у дома>, предлагающая широкий ассортимент доступных продуктов и товаров повседневного спроса. Она известна удобным расположением, частыми акциями и низкими ценами, что делает её популярной среди покупателей.",
        "image": "Фотки зданий/Осень3.png",
        "contact": "+7 (8162) 68-50-50",
        "tegs": "супермаркет Магазин продуктов",
        "contact2": "ул. Фёдоровский Ручей, 27, район Торговая сторона"
    },{
        "name": "Осень",
        "description": "«Осень» — российская сеть магазинов формата <у дома>, предлагающая широкий ассортимент доступных продуктов и товаров повседневного спроса. Она известна удобным расположением, частыми акциями и низкими ценами, что делает её популярной среди покупателей.",
        "image": "Фотки зданий/Осень5.png",
        "contact": "+7 (8162) 68-50-50",
        "tegs": "супермаркет Магазин продуктов",
        "contact2": "Большая Московская ул., 126"
    },{
        "name": "Верный",
        "description": "«Верный» — российская сеть магазинов <у дома>, предлагающая широкий ассортимент продуктов и товаров повседневного спроса. Она известна низкими ценами и удобным расположением, что делает её популярной среди покупателей.",
        "image": "Фотки зданий/Верный.png",
        "contact": "8 (800) 250-66-48",
        "tegs": "Магазин продуктов",
        "contact2": "Стратилатовская ул., 12, район Софийская сторона"
    },{
        "name": "Верный",
        "description": "«Верный» — российская сеть магазинов <у дома>, предлагающая широкий ассортимент продуктов и товаров повседневного спроса. Она известна низкими ценами и удобным расположением, что делает её популярной среди покупателей.",
        "image": "Фотки зданий/Верный1.png",
        "contact": "8 (800) 250-66-48",
        "tegs": "Магазин продуктов",
        "contact2": "Воскресенский бул., 2/2, Привокзальный район"
    },{
        "name": "Десяточка",
        "description": "«Десяточка» — российская сеть магазинов формата <у дома>, предлагающая широкий ассортимент продуктов и товаров повседневного спроса. Она известна доступными ценами и удобным расположением, что делает её привлекательной для покупателей, стремящихся к экономии и удобству.",
        "image": "Фотки зданий/Десяточка.png",
        "contact": " ",
        "tegs": "Магазин продуктов",
        "contact2": "Десятинная ул., 2, район Софийская сторона"
    },{
        "name": "Градусы",
        "description": "«Градусы» — российская сеть магазинов формата «у дома», специализирующаяся на продаже продуктов питания высокого качества. Сеть известна своим разнообразным ассортиментом продуктов, в том числе экологически чистых и импортированных, а также удобным расположением магазинов.",
        "image": "Фотки зданий/Градусы.png",
        "contact": "+7 (905) 213-44-26",
        "tegs": "Магазин продуктов алкогольные напитки",
        "contact2": "Октябрьская ул., 24/12"
    },{
        "name": "Магазинъ",
        "description": "«Магазинъ» — российская сеть магазинов, предлагающая широкий ассортимент продуктов питания и товаров повседневного спроса. Она ориентирована на качество, доступные цены и удобное расположение, обеспечивая комфортный шопинг для покупателей.",
        "image": "Фотки зданий/Магазинъ.png",
        "contact": " ",
        "tegs": "Магазин продуктов",
        "contact2": "Воскресенский бул., 17/22, Привокзальный район"
    },{
        "name": "Светофор",
        "description": "«Светофор» — российская сеть дискаунтеров, предлагающая широкий ассортимент продуктов питания и товаров повседневного спроса по низким ценам. Магазины ориентированы на экономию, предоставляя покупателям возможность приобретать качественные товары без лишних затрат.",
        "image": "Фотки зданий/Светофор.png",
        "contact": " ",
        "tegs": "Магазин продуктов супермаркет",
        "contact2": "Колмовская наб., 3 • ТЦ Парус"
    },{
        "name": "Продукты 24",
        "description": "«Продукты 24» — российская сеть магазинов формата «у дома», предлагающая круглосуточный доступ к широкому ассортименту продуктов питания и товаров первой необходимости. Сеть ориентирована на удобство и оперативность обслуживания, обеспечивая покупателям возможность делать покупки в любое время.",
        "image": "Фотки зданий/Продукты 24.png",
        "contact": " ",
        "tegs": "Магазин продуктов",
        "contact2": "Колмовская наб., 3 • ТЦ Парус"
    },
    #Музеи
    {
        "name": "Музей народного деревянного зодчества Витославлицы",
        "description": "Музей «Витославлицы» — это музей деревянного зодчества под открытым небом, расположенный в живописном месте на берегу реки.",
        "image": "Фотки зданий/Витославлицы.png",
        "contact": "+7 (921) 020-54-22",
        "tegs": "Музей достопримечательность",
        "contact2": "Юрьевское ш., 15"
    },{
        "name": "Новгородский кремль",
        "description": "Новгородский кремль — это музейный комплекс, который является одной из главных достопримечательностей Великого Новгорода.",
        "image": "Фотки зданий/Новгородский кремль.png",
        "contact": "+7 (8162) 90-93-92",
        "tegs": "Музей достопримечательность",
        "contact2": "Новгородский кремль, 25"
    },{
        "name": "Центр музыкальных древностей В.И. Поветкина",
        "description": "Центр музыкальных древностей В.И. Поветкина — это уникальное место, где можно услышать звучание редких и самобытных инструментов, которые могли бы быть утрачены навсегда.",
        "image": "Фотки зданий/Поветкина.png",
        "contact": "+7 (8162) 63-50-19",
        "tegs": "Музей достопримечательность культурный центр",
        "contact2": "Ильина ул., 9Б, район Торговая сторона"
    },{
        "name": "Киномузей Валерия Рубцова",
        "description": "Киномузей Валерия Рубцова — это частная коллекция киноаппаратуры и других экспонатов, связанных с историей кино.",
        "image": "Фотки зданий/Рубцова.png",
        "contact": "+7 (911) 642-71-79",
        "tegs": "Музей",
        "contact2": "ул. Рогатица, 16/21, район Торговая сторона"
    },{
        "name": "Новгородский государственный объединенный музей-заповедник, главное здание музея",
        "description": "Новгородский музей-заповедник — это место, где вы можете погрузиться в историю Новгородской земли. Здесь вы найдете множество археологических находок, позволяющих узнать много нового из истории Новгорода.",
        "image": "Фотки зданий/музей-заповедник.png",
        "contact": "+7 (921) 730-93-92",
        "tegs": "Музей",
        "contact2": "район Софийская сторона, Новгородский кремль, 4"
    },{
        "name": "Музей изобразительных искусств",
        "description": "Музей изобразительных искусств в Великом Новгороде — это место, где можно увидеть работы известных русских художников, таких как Шишкин, Айвазовский, Репин и Куинджи, а также посетить временные выставки.",
        "image": "Фотки зданий/изобразительных искусств.png",
        "contact": "+7 (921) 730-93-92",
        "tegs": "Музей достопримечательность",
        "contact2": "площадь Победы-Софийская, 2"
    },{
        "name": "Музейный цех фарфора",
        "description": "«Музейный цех фарфора» является частью Музея художественной культуры Новгородской земли в Десятинном монастыре.",
        "image": "Фотки зданий/цех фарфора.png",
        "contact": "+7 (911) 644-02-91",
        "tegs": "Музей",
        "contact2": "район Софийская сторона, Десятинный монастырь, 6"
    },{
        "name": "Государственный музей художественной культуры Новгородской земли",
        "description": "Музей художественной культуры Новгородской земли — это музей, расположенный на территории Десятинного монастыря, памятника архитектуры XIV-XIX веков. В музее представлены произведения искусства новгородских художников конца ХХ — начала XXI веков.",
        "image": "Фотки зданий/художественной культуры.png",
        "contact": "+7 (921) 730-93-92",
        "tegs": "Музей выставочный центр",
        "contact2": "площадь Победы-Софийская, 2"
    },{
        "name": "Владычная палата",
        "description": "Владычная палата — это уникальный памятник древнерусской архитектуры, выполненный в стиле западноевропейской готики. Это единственное сохранившееся гражданское сооружение средневекового Новгорода.",
        "image": "Фотки зданий/Владычная палата.png",
        "contact": "+7 (921) 207-37-70",
        "tegs": "Музей достопримечательность",
        "contact2": "район Софийская сторона, Новгородский кремль, 14А"
    },{
        "name": "Церковь Спаса Преображения на Ильине улице",
        "description": "Церковь Спаса Преображения на Ильине улице — это уникальный памятник древнерусской архитектуры XIV века, известный своими великолепными фресками, выполненными выдающимся византийским художником Феофаном Греком.",
        "image": "Фотки зданий/Церковь Спаса.png",
        "contact": "+7 (8162) 90-93-92",
        "tegs": "Музей достопримечательность",
        "contact2": "Ильина ул., 26А, район Торговая сторона, Судейский городок 1, Кремль"
    },{
        "name": "Мастерская-музей реалистической живописи Александра Варенцова",
        "description": "Музей реалистической живописи А. Варенцова — это место, где взрослые и дети могут раскрыть свой творческий потенциал.",
        "image": "Фотки зданий/Александра Варенцова.png",
        "contact": "+7 (911) 644-43-42",
        "tegs": "Музей Курсы и мастер-классы Художественная мастерская",
        "contact2": "Каберова-Власьевская ул., 22 • этаж 3"
    },{
        "name": "Музей письменности",
        "description": "Музей письменности — это современный интерактивный музей, который рассказывает об истории письменности и берестяных грамотах. Здесь можно увидеть оригинальные берестяные грамоты и их копии, а также старинные рукописные и первые печатные книги.",
        "image": "Фотки зданий/Музей письменности.png",
        "contact": "+7 (921) 730-93-92",
        "tegs": "Музей",
        "contact2": "район Софийская сторона, Новгородский кремль, 12"
    },{
        "name": "Детский музейный центр",
        "description": "Детский музейный центр в Великом Новгороде — это место, где дети могут узнать много интересного о древнем городе и его жителях.",
        "image": "Фотки зданий/Детский музейный центр.png",
        "contact": "+7 (8162) 77-40-54",
        "tegs": "Музей",
        "contact2": "район Софийская сторона, Новгородский кремль, Студийский городок 3"
    },{
        "name": "Алексеевская Белая башня",
        "description": "Алексеевская Белая башня — это интерактивный музей, рассказывающий о героической обороне Великого Новгорода от шведского вторжения начала XVII века. В музее представлены как подлинные экспонаты, так и реконструкция некоторых предметов одежды, воинского снаряжения и оружия.",
        "image": "Фотки зданий/Детский музейный центр.png",
        "contact": "+7 (921) 730-93-92",
        "tegs": "Музей достопримечательность",
        "contact2": "Троицкая ул., 15А"
    },{
        "name": "Зал воинской славы",
        "description": "Зал воинской славы в Великом Новгороде — часть музейного комплекса, посвященного военной доблести и патриотизму России. Он находится в Новгородском музее-заповеднике и включает экспозицию, посвященную важным событиям, связанным с защитой Родины.",
        "image": "Фотки зданий/Зал воинской славы.png",
        "contact": "+7 (8162) 94-87-64",
        "tegs": "Музей",
        "contact2": "Чудинцева ул., 11/62, район Софийская сторона"
    },{
        "name": "Музей Утюга",
        "description": "«Музей утюга» — это частная коллекция утюгов всех видов (цельнолитые, со сменными ручками и вкладышами, на угле, на газе, на спирте, на электричестве, сувенирные), XVIII-XX веков, из разных стран (СССР, Франция, США, Польша, Тунис).",
        "image": "Фотки зданий/Музей Утюга.png",
        "contact": "+7 (921) 203-90-47",
        "tegs": "Музей",
        "contact2": "Юрьевское ш., 6Б"
    },{
        "name": "Новгородский музей-заповедник, экскурсионный отдел",
        "description": "Новгородский музей-заповедник, экскурсионный отдел — это место, где вы можете заказать индивидуальную или групповую экскурсию, а также воспользоваться услугами профессионального экскурсовода.",
        "image": "Фотки зданий/музей-заповедник1.png",
        "contact": "+7 (921) 207-37-70",
        "tegs": "Музей",
        "contact2": "ул. Мерецкова-Волосова, 2, район Софийская сторона"
    },{
        "name": "Центр противопожарной пропаганды и общественных связей",
        "description": "Центр противопожарной пропаганды и общественных связей в Великом Новгороде — специализированный музей, посвященный пожарной безопасности и истории пожарной службы. Здесь представлены экспозиции, знакомящие посетителей с основами безопасности и методами тушения пожаров.",
        "image": "Фотки зданий/Центр противопожарной пропаганды.png",
        "contact": " ",
        "tegs": "Музей",
        "contact2": "ул. Михайлова, 27, район Торговая сторона"
    },{
        "name": "Стены и башни Новгородского кремля",
        "description": "Музей «Стены и башни Новгородского кремля» — это место, где можно насладиться красотой и величием этого древнего сооружения.",
        "image": "Фотки зданий/Стены и башни.png",
        "contact": "+7 (8162) 77-37-38",
        "tegs": "Музей",
        "contact2": "Новгородский кремль"
    },{
        "name": "Лекторий",
        "description": "Лекторий в Великом Новгороде — образовательное пространство в одном из музеев, предлагающее лекции, семинары и мастер-классы. Его цель — популяризация знаний в истории, культуре и искусстве, а также повышение осведомленности о социальных и экологических вопросах.",
        "image": "Фотки зданий/Лекторий.png",
        "contact": "+7 (8162) 77-37-63",
        "tegs": "Музей",
        "contact2": "район Софийская сторона, Новгородский кремль, 7"
    },{
        "name": "Дирекция Новгородского государственного объединённого музея-заповедника",
        "description": "Дирекция Новгородского государственного объединенного музея-заповедника в Великом Новгороде управляет музеем, который включает несколько исторических и культурных объектов. Музей играет ключевую роль в сохранении и популяризации культурного наследия региона, проводя выставки и образовательные программы.",
        "image": "Фотки зданий/музея-заповедника2.png",
        "contact": "+7 (8162) 77-36-08",
        "tegs": "Музей",
        "contact2": "район Софийская сторона, Новгородский кремль, 9"
    },{
        "name": "Усадебный дом А.А. Орловой-Чесменской",
        "description": "Усадебный дом А.А. Орловой-Чесменской — это музей, расположенный в музее-заповеднике «Витославлицы». Он представляет собой двухэтажный дом, в котором можно увидеть экспозицию, посвященную жизни и деятельности графини Орловой-Чесменской.",
        "image": "Фотки зданий/Усадебный дом.png",
        "contact": " ",
        "tegs": "Музей достопримечательность",
        "contact2": "Новгородская область, Великий Новгород, Юрьево"
    },{
        "name": "Музей истории органов внутренних дел Новгородской области культурного центра УМВД России по Новгородской области",
        "description": "Музей истории органов внутренних дел Новгородской области, расположенный в культурном центре УМВД России, посвящен истории правоохранительных органов региона. Он представляет собой площадку с экспонатами, документами и фотографиями, иллюстрирующими развитие милиции и полиции в области.",
        "image": "Фотки зданий/Усадебный дом.png",
        "contact": " ",
        "tegs": "Музей",
        "contact2": "просп. Александра Корсунова, 34"
    },{
        "name": "Церковь Успения Пресвятой Богородицы на Волотовом поле",
        "description": "Лекторий в Великом Новгороде — образовательное пространство в одном из музеев, предлагающее лекции, семинары и мастер-классы. Его цель — популяризация знаний в истории, культуре и искусстве, а также повышение осведомленности о социальных и экологических вопросах.",
        "image": "Фотки зданий/Музей истории органов внутренних дел.png",
        "contact": "+7 (921) 730-93-92",
        "tegs": "Музей Православный храм достопримечательность",
        "contact2": "Речная ул., 38, д. Волотово"
    },
    #Театр
    {
        "name": "Новгородский областной академический театр драмы имени Достоевского",
        "description": "Новгородский театр драмы носит имя Ф. М. Достоевского с 1997 года. Главные и знаковые спектакли в театре поставлены на основе романов писателя.",
        "image": "Фотки зданий/Достоевского.png",
        "contact": "+7 (8162) 77-27-77",
        "tegs": "Театр",
        "contact2": "Великая ул., 14"
    },{
        "name": "Театр для детей и молодежи Малый",
        "description": "Театр для детей и молодежи «Малый» — это место, где каждый найдет что-то интересное для себя. В репертуаре театра есть спектакли как для детей, так и для взрослых, а также постановки, которые затрагивают важные темы, такие как взросление и взаимоотношения людей с окружающим миром.",
        "image": "Фотки зданий/Малый.png",
        "contact": "+7 (8162) 65-54-53",
        "tegs": "Театр",
        "contact2": "просп. Мира, 32А, Западный район"
    },
    #Библиотека
    {
        "name": "Молодежная библиотека",
        "description": "Молодежная библиотека — это специализированное учреждение, ориентированное на подростков и молодых людей. Ее основная цель — содействие развитию читательской культуры и предоставление доступа к информации для учебы и саморазвития.",
        "image": "Фотки зданий/Молодежная.png",
        "contact": "+7 (8162) 61-61-55",
        "tegs": "Библиотека",
        "contact2": "ул. Кочетова, 37, корп. 1, Западный район"
    },{
        "name": "Библиотечный центр Читай-Город",
        "description": "Библиотечный центр <<Читай-Город>> — это современное учреждение, направленное на развитие читательской культуры и поддержку молодежи. Центр предлагает широкий выбор литературы, включая художественные и учебные книги, электронные ресурсы и мультимедиа.",
        "image": "Фотки зданий/Читай-город.png",
        "contact": "+7 (8162) 62-03-61",
        "tegs": "Библиотека",
        "contact2": "просп. Мира, 1, Западный район"
    },
    #Парки
    {
        "name": "Веряжский парк",
        "description": "Веряжский парк — это место, где можно провести время с семьей и друзьями, гуляя по ухоженным дорожкам и наслаждаясь свежим воздухом.",
        "image": "Фотки зданий/Веряжский.png",
        "contact": " ",
        "tegs": "Парк культуры и отдыха сквер лесопарк",
        "contact2": "Великий Новгород, Веряжский парк"
    },{
        "name": "сквер Кочетова",
        "description": "Сквер Кочетова — это уютное зеленое пространство, предназначенное для отдыха и прогулок. Он расположен в живописном районе и предлагает посетителям красивые аллеи, скамейки и цветочные клумбы. Сквер является популярным местом для встреч, семейных прогулок и культурных мероприятий. Здесь",
        "image": "Фотки зданий/Кочетова.png",
        "contact": " ",
        "tegs": "Парк культуры и отдыха сквер лесопарк",
        "contact2": "Великий Новгород, сквер Кочетова"
    },{
        "name": "сквер Минутка",
        "description": "Сквер «Минутка» находится в Великом Новгороде на улице Зелинского, между школой № 35 и детским садом № 94. В рамках благоустройства сквера планируется создание новых пешеходных дорожек, площадки с солнечными часами и сохранение существующих пешеходных дорожек и площадок со скамейками.",
        "image": "Фотки зданий/Минутка.png",
        "contact": " ",
        "tegs": "Парк культуры и отдыха сквер лесопарк",
        "contact2": "Великий Новгород, сквер Минутка"
    },{
        "name": "сквер Защитников Отечества",
        "description": "Сквер Защитников Отечества расположен в Великом Новгороде на проспекте Александра Корсунова. В нём планируется установить мемориальный комплекс сотрудникам органов внутренних дел, погибшим при исполнении служебных обязанностей.",
        "image": "Фотки зданий/Музей истории органов внутренних дел.png",
        "contact": " ",
        "tegs": "Парк культуры и отдыха сквер лесопарк",
        "contact2": "Великий Новгород, сквер Защитников Отечества"
    },
    #Кинотеатры
    {
        "name": "Мираж Синема",
        "description": "«Мираж Синема» — современный кинотеатр с комфортными залами, предлагающий широкий выбор фильмов и высокое качество звука и изображения. Здесь можно насладиться попкорном и напитками во время просмотра.",
        "image": "Фотки зданий/Мираж Синема.png",
        "contact": "+7 (812) 677-60-60",
        "tegs": "Кинотеатр",
        "contact2": "ул. Ломоносова, 29 • этаж 3"
    },{
        "name": "Новгород",
        "description": "Кинотеатр «Новгород» — это уютный кинотеатр, предлагающий разнообразные фильмы, включая новинки и классические картины. Он оснащён современным оборудованием для комфортного просмотра и предоставляет услуги по продаже закусок и напитков.",
        "image": "Фотки зданий/Новгород.png",
        "contact": "+7 (8162) 70-00-53",
        "tegs": "Кинотеатр",
        "contact2": "ул. Ломоносова, 9 • этаж 1"
    },{
        "name": "Мультимедийный центр Россия",
        "description": "Мультимедийный центр «Россия» — современное заведение, предлагающее широкий выбор фильмов, выставок и культурных мероприятий. Оснащённый новейшими технологиями, центр обеспечивает комфортный просмотр и уникальный опыт для зрителей.",
        "image": "Фотки зданий/Мультимедийный центр Россия.png",
        "contact": "+7 (8162) 77-73-36",
        "tegs": "Кинотеатр",
        "contact2": "ул. Черняховского, 66, район Софийская сторона"
    },{
        "name": "Планетарий Орион",
        "description": "Планетарий «Орион» — это место, где можно посмотреть познавательные фильмы о космосе и солнечной системе, а также поучаствовать в мастер-классах.",
        "image": "Фотки зданий/Орион.png",
        "contact": "+7 (908) 225-20-20",
        "tegs": "Кинотеатр Планетарий",
        "contact2": "Большая Санкт-Петербургская ул., 39"
    },
    #Спортплощадка
    {
        "name": "Спортплощадка",
        "description": "Спортплощадка — это территория для занятий спортом, оборудованная футбольными полями, баскетбольными и волейбольными площадками. Она предназначена для активного отдыха и тренировок для всех возрастов.",
        "image": "Фотки зданий/Спортплощадка.png",
        "contact": " ",
        "tegs": "Спортплощадка",
        "contact2": "Великий Новгород, район Софийская сторона, 108-й квартал"
    },{
        "name": "Спортплощадка, воркаут",
        "description": "Спортплощадка — это территория для занятий спортом, оборудованная футбольными полями, баскетбольными и волейбольными площадками. Она предназначена для активного отдыха и тренировок для всех возрастов.",
        "image": "Фотки зданий/воркаут.png",
        "contact": "+7 (8162) 73-24-06",
        "tegs": "Спортплощадка",
        "contact2": "Прусская ул., 4"
    },
    #Отели
    {
        "name": "Вишневый Рояль",
        "description": "Отель «Вишневый Рояль» расположен в тихом историческом районе Великого Новгорода, в 10 минутах ходьбы от набережной реки Волхов и в 15 минутах ходьбы от Новгородского Кремля.",
        "image": "Фотки зданий/Вишневый Рояль.png",
        "contact": "+7 (8162) 20-04-75",
        "tegs": "Гостиница",
        "contact2": "Славная ул., 20, район Торговая сторона"
    },{
        "name": "Карелинн",
        "description": "Гостиница «Карелинн» расположена в центре Великого Новгорода, в 7 минутах ходьбы от Кремля. Гостям предлагается проживание в небольших, но уютных номерах с современным дизайном и всем необходимым для комфортного отдыха.",
        "image": "Фотки зданий/Карелинн.png",
        "contact": "+7 (911) 612-30-30",
        "tegs": "Гостиница",
        "contact2": "Большая Санкт-Петербургская ул., 21 этаж 2"
    },
]
#Сайт
@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return jsonify({'success': False, 'message': "Пароли не совпадают."})

        success, message = register_user(username, password)

        if success:
            return jsonify({'success': True, 'username': username})
        else:
            return jsonify({'success': False, 'message': message})

    return render_template("index.html", title="Городской гид")

@app.route("/search", methods=["POST"])
def search():
    query = request.form.get("query")
    results = []
    if query:
        # Разбиваем запрос на отдельные слова
        query_words = query.lower().split()
        # Ищем рестораны, которые содержат хотя бы одно из слов или букв в названии или описании
        results = [
            restaurant for restaurant in restaurants
            if any(
                word in restaurant["name"].lower() or
                word in restaurant["description"].lower() or
                word in re.sub(r'\d+', '', restaurant["contact2"]).lower() or  # Только адрес
                word in restaurant["tegs"].lower()
                for word in query_words
            )
        ]

        print(f"Search query: {query}")  # Для отладки
        print(f"Results found: {len(results)} results")  # Лучше выводить количество

    return render_template("results.html", query=query, results=results, title="Результаты поиска")

@app.route("/Restaurant", methods=["GET"])
def Restaurant():
    print(url_for("Restaurant"))
    restaurants = Place.query.filter_by(category='Ресторан').all()
    return render_template("Restaurant.html",
                           title="Рестораны",
                           restaurants=restaurants)

@app.route('/restaurant/<int:id>')
def restaurant_page(id):
    place = Place.query.get_or_404(id)
    template_map = {
        2: 'ЛичныеСтраницы/lambs.html',
        3: 'ЛичныеСтраницы/test.html',
    }
    template = template_map.get(id, 'default_restaurant.html')
    return render_template(template, place=place)

@app.route("/Coffee", methods=["GET"])
def Coffee():
    print(url_for("Coffee"))
    coffee = Place.query.filter_by(category='Кафе').all()
    return render_template("Coffee.html",
                           title="Кафе",
                           coffee=coffee)

@app.route("/shop", methods=["GET"])
def shop():
    print(url_for("shop"))
    shop = Place.query.filter_by(category='Магазин').all()
    return render_template("shop.html",
                           title="Магазины",
                           shop=shop)

@app.route("/museums", methods=["GET"])
def museums():
    print(url_for("museums"))
    museums = Place.query.filter_by(category='Музей').all()
    return render_template("museums.html",
                           title="Музеи",
                           museums=museums)

@app.route("/theatre", methods=["GET"])
def theatre():
    print(url_for("theatre"))
    theatre = Place.query.filter_by(category='Театр').all()
    return render_template("theatre.html",
                           title="Театры",
                           theatre=theatre)

@app.route("/library", methods=["GET"])
def library():
    print(url_for("library"))
    library = Place.query.filter_by(category='Библиотека').all()
    return render_template("library.html",
                           title="Библиотеки",
                           library=library)

@app.route("/park", methods=["GET"])
def park():
    print(url_for("park"))
    park = Place.query.filter_by(category='Парк').all()
    return render_template("park.html",
                           title="Парки",
                           park=park)

@app.route("/cinema", methods=["GET"])
def cinema():
    print(url_for("cinema"))
    cinema = Place.query.filter_by(category='Кинотеатр').all()
    return render_template("cinema.html",
                           title="Кинотеатр",
                           cinema=cinema)

@app.route("/sports", methods=["GET"])
def sports():
    print(url_for("sports"))
    sports = Place.query.filter_by(category='Спортплощадка').all()
    return render_template("sports.html",
                           title="Спортплощадка",
                           sports=sports)

@app.route("/church", methods=["GET"])
def church():
    print(url_for("church"))
    church = Place.query.filter_by(category='Церковь').all()
    return render_template("church.html",
                           title="Церковь",
                           church=church)

@app.route("/hotels", methods=["GET"])
def hotels():
    print(url_for("hotels"))
    hotels = Place.query.filter_by(category='Гостиница').all()
    return render_template("hotels.html",
                           title="Отели",
                           hotels=hotels)

@app.route("/favorites", methods=["GET"])
def favorites():
    print(url_for("favorites"))
    return render_template("favorites.html", title="Избранное")

#Личные страницы

@app.route('/Restaurant/lambs')
def lambs():
    place = Place.query.get_or_404(2)  # ID Барашек
    return render_template('ЛичныеСтраницы/lambs.html', place=place)

@app.route('/Restaurant/test')
def test():
    return render_template('ЛичныеСтраницы/test.html')

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'message': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'message': 'Internal server error'}), 500

if __name__ == "__main__":
    app.run(debug=True)