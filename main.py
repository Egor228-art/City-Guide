import hashlib
import re
import os
import pytz
import math
import sqlite3

from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask import Flask, jsonify, render_template, request, url_for, session
from datetime import datetime, timezone, timedelta
from flask_migrate import Migrate
from sqlalchemy import text

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
MOSCOW_TZ = pytz.timezone('Europe/Moscow')

db = SQLAlchemy(app)
admin = Admin(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db) #Обнавление столбцов в бд
def get_moscow_time():
    return datetime.now(MOSCOW_TZ).replace(tzinfo=None)  # Убираем временную зону для совместимости

# Убедитесь, что эти настройки добавлены перед созданием приложения
UPLOAD_FOLDER = os.path.join('static', 'Фотки зданий')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# Создаем папку при запуске
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Определяем модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

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
    tags = db.Column(db.Text, nullable=True)
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
    created_at = db.Column(db.DateTime, default=get_moscow_time)
    updated_at = db.Column(db.DateTime)  # Добавляем поле для времени редактирования
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)
    user_token = db.Column(db.String(255))  # Для анонимных пользователей
    device_fingerprint = db.Column(db.String(255))  # Добавляем это поле
    ip_address = db.Column(db.String(45))  # Для ограничения по IP
    user_ratings = db.Column(db.JSON, default=dict)

# def register_user(username, password, secret_key):

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

def update_restaurant_stats(restaurant_id):
    reviews = Review.query.filter_by(restaurant_id=restaurant_id).all()

    if not reviews:
        return

    total_rating = sum(review.rating for review in reviews)
    review_count = len(reviews)
    average_rating = total_rating / review_count

    # ИСПОЛЬЗУЙТЕ Restaurant.query.get() вместо db.session.get()
    restaurant = Restaurant.query.get(restaurant_id)
    if not restaurant:
        restaurant = Restaurant(id=restaurant_id, name=f"Restaurant {restaurant_id}")
        db.session.add(restaurant)

    restaurant.total_rating = average_rating
    restaurant.review_count = review_count
    db.session.commit()

# Псевдокод для серверной проверки
def check_review_limit(user_token, ip_address, restaurant_id):
    # Проверяем количество отзывов с этим токеном за последние 24 часа
    reviews_count = Review.query.filter(
        Review.user_token == user_token,
        Review.created_at > datetime.now() - timedelta(hours=24)
    ).count()

    # Проверяем по IP (дополнительная защита)
    ip_reviews_count = Review.query.filter(
        Review.ip_address == ip_address,
        Review.created_at > datetime.now() - timedelta(hours=24)
    ).count()

    return reviews_count < 3 and ip_reviews_count < 5  # Лимиты

# В модель Review добавим метод проверки времени
def can_edit(self):
    """Проверка возможности редактирования (3 часа)"""
    time_diff = datetime.now(timezone.utc) - self.created_at
    return time_diff.total_seconds() <= 3 * 3600

def can_delete(self):
    """Проверка возможности удаления (6 часов)"""
    time_diff = datetime.now(timezone.utc) - self.created_at
    return time_diff.total_seconds() <= 6 * 3600

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

# Обновим endpoint проверки редактирования
@app.route('/api/reviews/<int:review_id>/permissions', methods=['GET'])
def get_review_permissions(review_id):
    try:
        review = Review.query.get_or_404(review_id)
        user_token = request.args.get('user_token')
        device_fingerprint = request.args.get('device_fingerprint')

        if not user_token or review.user_token != user_token:
            return jsonify({
                'can_edit': False,
                'can_delete': False,
                'reason': 'Не ваш отзыв'
            })

        # Проверка устройства
        if review.device_fingerprint != device_fingerprint:
            return jsonify({
                'can_edit': False,
                'can_delete': False,
                'reason': 'Доступ только с того же устройства'
            })

        return jsonify({
            'can_edit': review.can_edit(),
            'can_delete': review.can_delete(),
            'time_left_edit': max(0, 3*3600 - (datetime.now(timezone.utc) - review.created_at).total_seconds()),
            'time_left_delete': max(0, 6*3600 - (datetime.now(timezone.utc) - review.created_at).total_seconds())
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reviews/<int:review_id>/can_edit', methods=['GET'])
def can_edit_review(review_id):
    try:
        review = Review.query.get_or_404(review_id)
        user_token = request.args.get('user_token')
        device_fingerprint = request.args.get('device_fingerprint')

        if not user_token or review.user_token != user_token:
            return jsonify({'can_edit': False, 'reason': 'Не ваш отзыв'})

        # Проверка времени (3 часа)
        time_diff = datetime.now(timezone.utc) - review.created_at
        if time_diff.total_seconds() > 3 * 3600:
            return jsonify({'can_edit': False, 'reason': 'Время редактирования истекло'})

        # Дополнительная проверка устройства
        if review.device_fingerprint != device_fingerprint:
            return jsonify({'can_edit': False, 'reason': 'Редактирование только с того же устройства'})

        return jsonify({
            'can_edit': True,
            'time_left': 3 * 3600 - time_diff.total_seconds()
        })

    except Exception as e:
        return jsonify({'can_edit': False, 'reason': 'Ошибка сервера'}), 500


# Проверка структуры таблицы review
def check_review_table_structure():
    try:
        conn = sqlite3.connect('instance/database.db')
        cursor = conn.cursor()

        # Проверяем последние 5 отзывов
        cursor.execute("SELECT id, user_token, device_fingerprint FROM review ORDER BY id DESC LIMIT 5")
        reviews = cursor.fetchall()

        print("Последние 5 отзывов:")
        for review in reviews:
            print(f"  ID: {review[0]}, Token: {review[1]}, Fingerprint: {review[2]}")

        conn.close()
    except Exception as e:
        print(f"Ошибка при проверке: {e}")


def check_columns_exist():
    try:
        conn = sqlite3.connect('instance/database.db')
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(review)")
        columns = [column[1] for column in cursor.fetchall()]

        print("Столбцы в таблице review:")
        for column in columns:
            print(f"  - {column}")

        # Проверяем наличие нужных столбцов
        required_columns = ['user_token', 'device_fingerprint']
        for col in required_columns:
            if col in columns:
                print(f"✓ {col} exists")
            else:
                print(f"✗ {col} missing")

        conn.close()
    except Exception as e:
        print(f"Ошибка при проверке: {e}")


check_columns_exist()

@app.route('/api/reviews/<int:review_id>', methods=['PUT'])
def edit_review(review_id):
    try:
        print(f"=== ОБНОВЛЕНИЕ ОТЗЫВА {review_id} ===")

        data = request.get_json()
        print(f"Полученные данные: {data}")

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Получаем отзыв
        review = Review.query.get(review_id)
        if not review:
            return jsonify({'error': 'Review not found'}), 404

        # Проверяем обязательные поля
        user_token = data.get('user_token')
        device_fingerprint = data.get('device_fingerprint')

        print(f"User token из запроса: {user_token}")
        print(f"User token в отзыве: {review.user_token}")
        print(f"Device fingerprint из запроса: {device_fingerprint}")
        print(f"Device fingerprint в отзыве: {review.device_fingerprint}")

        if not user_token:
            return jsonify({'error': 'User token required'}), 400

        if not device_fingerprint:
            return jsonify({'error': 'Device fingerprint required'}), 400

        # ВАЖНОЕ ИСПРАВЛЕНИЕ: Если отзыв без user_token, ОБНОВЛЯЕМ его
        if review.user_token is None:
            print("🔄 Отзыв без user_token - обновляем токены")
            review.user_token = user_token
            review.device_fingerprint = device_fingerprint
        # Если user_token не совпадает - ошибка (кроме случая когда это legacy)
        elif review.user_token != user_token:
            print("❌ Ошибка: несовпадение user_token")
            return jsonify({'error': 'Permission denied - user token mismatch'}), 403

        # Проверяем время (3 часа)
        now_utc = datetime.utcnow()
        if review.created_at.tzinfo is not None:
            created_at_naive = review.created_at.replace(tzinfo=None)
        else:
            created_at_naive = review.created_at

        time_diff = now_utc - created_at_naive
        hours_diff = time_diff.total_seconds() / 3600
        print(f"Прошло времени с создания: {hours_diff:.2f} часов")

        if hours_diff > 3:
            print("❌ Время редактирования истекло")
            return jsonify({'error': 'Editing time expired (3 hours limit)'}), 403

        # Обновляем поля
        if 'rating' in data:
            new_rating = data['rating']
            print(f"🔄 Обновление рейтинга: {review.rating} -> {new_rating}")
            review.rating = new_rating

        if 'comment' in data:
            new_comment = data['comment']
            print(f"🔄 Обновление комментария: {review.comment} -> {new_comment}")
            review.comment = new_comment

        # Устанавливаем время обновления
        review.updated_at = datetime.utcnow()
        print(f"🕐 Установлено время обновления: {review.updated_at}")

        # Сохраняем в БД
        db.session.commit()
        print("✅ Изменения успешно сохранены в БД")

        # Обновляем статистику ресторана
        update_restaurant_stats(review.restaurant_id)
        print("📊 Статистика ресторана обновлена")

        # ВАЖНО: Возвращаем ОБНОВЛЕННЫЕ данные
        response_data = {
            'success': True,
            'message': 'Review updated successfully',
            'review': {
                'id': review.id,
                'username': review.username,
                'rating': review.rating,
                'comment': review.comment,
                'updated_at': review.updated_at.isoformat() if review.updated_at else None,
                'user_token': review.user_token,  # ✅ Теперь будет правильный user_token
                'device_fingerprint': review.device_fingerprint,  # ✅ Теперь будет правильный device_fingerprint
                'created_at': review.created_at.isoformat(),
                'likes': review.likes or 0,
                'dislikes': review.dislikes or 0,
                'user_ratings': review.user_ratings or {}
            }
        }

        print(f"📤 Отправляем ответ: {response_data}")
        return jsonify(response_data)

    except Exception as e:
        print(f"❌ ОШИБКА: {str(e)}")
        import traceback
        traceback.print_exc()
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500

def check_database_structure():
    try:
        conn = sqlite3.connect('instance/database.db')
        cursor = conn.cursor()

        # Проверяем структуру таблицы review
        cursor.execute("PRAGMA table_info(review)")
        columns = cursor.fetchall()

        print("=== СТРУКТУРА ТАБЛИЦЫ REVIEW ===")
        for column in columns:
            print(f"Column: {column[1]}, Type: {column[2]}, Nullable: {column[3]}")

        # Проверяем есть ли данные в столбцах
        cursor.execute("SELECT id, user_token, device_fingerprint FROM review LIMIT 5")
        sample_data = cursor.fetchall()

        print("=== ДАННЫЕ В ТАБЛИЦЕ ===")
        for row in sample_data:
            print(f"ID: {row[0]}, User Token: {row[1]}, Device Fingerprint: {row[2]}")

        conn.close()
    except Exception as e:
        print(f"Ошибка при проверке БД: {e}")

check_database_structure()

@app.route('/api/reviews/<int:review_id>/can_edit', methods=['GET'])
def check_can_edit(review_id):
    try:
        review = Review.query.get_or_404(review_id)

        # Получаем данные из запроса
        user_token = request.args.get('user_token')
        device_fingerprint = request.args.get('device_fingerprint')

        if not user_token or not device_fingerprint:
            return jsonify({'can_edit': False, 'reason': 'Недостаточно данных'}), 400

        can_edit, reason = can_edit_review(
            review,
            user_token,
            device_fingerprint,
            request.remote_addr
        )

        return jsonify({
            'can_edit': can_edit,
            'reason': reason,
            'time_left': get_time_left(review.created_at) if can_edit else None
        })

    except Exception as e:
        return jsonify({'can_edit': False, 'reason': 'Ошибка сервера'}), 500


def get_time_left(created_at):
    """Возвращает оставшееся время для редактирования в секундах"""
    time_passed = datetime.now(timezone.utc) - created_at
    time_left = 3 * 3600 - time_passed.total_seconds()
    return max(0, time_left)  # Не отрицательное значение

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


# Добавьте эту функцию для проверки лимита отзывов
def check_review_limit_per_restaurant(user_token, restaurant_id):
    """Проверяет лимит отзывов (1 отзыв в день на ресторан)"""
    try:
        # Проверяем отзывы за последние 24 часа для этого пользователя и ресторана
        time_limit = datetime.now() - timedelta(hours=24)

        recent_reviews_count = Review.query.filter(
            Review.user_token == user_token,
            Review.restaurant_id == restaurant_id,
            Review.created_at >= time_limit
        ).count()

        return recent_reviews_count < 1
    except Exception as e:
        print(f"Error checking review limit: {e}")
        return True

@app.route('/api/reviews/<int:review_id>', methods=['PUT', 'DELETE'])
def handle_single_review(review_id):
    if request.method == 'PUT':
        return update_review(review_id)
    elif request.method == 'DELETE':
        return delete_review(review_id)


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

    ratings = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    for review in reviews:
        ratings[review.rating] += 1

    return jsonify({
        'average_rating': average_rating,
        'total_reviews': total_reviews,
        'ratings': ratings
    })


@app.route('/api/restaurants/<string:restaurant_id>', methods=['GET'])
def get_restaurant(restaurant_id):
    print(f"DEBUG: restaurant_id = {restaurant_id}, type = {type(restaurant_id)}")

    # Добавьте эту проверку
    if callable(restaurant_id):
        print("ERROR: restaurant_id is a function! This shouldn't happen.")
        # Попробуем получить ID из URL параметров
        restaurant_id = request.args.get('restaurant_id', 'lambs')
        print(f"Using fallback ID: {restaurant_id}")


    try:
        restaurant = db.session.get(Restaurant, restaurant_id)
        if not restaurant:
            return jsonify({'error': 'Ресторан не найден'}), 404

        return jsonify({
            'id': restaurant.id,
            'name': restaurant.name,
            'total_rating': restaurant.total_rating,
            'review_count': restaurant.review_count
        })
    except Exception as e:
        print(f"Error in get_restaurant: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Маршрут для получения отзывов
@app.route('/api/reviews')
def get_reviews():
    restaurant_id = request.args.get('restaurant_id')
    if not restaurant_id:
        return jsonify({'error': 'restaurant_id is required'}), 400

    try:
        reviews = Review.query.filter_by(restaurant_id=restaurant_id) \
            .order_by(Review.created_at.desc()) \
            .all()

        reviews_data = []
        for review in reviews:
            review_data = {
                'id': review.id,
                'username': review.username,
                'rating': review.rating,
                'comment': review.comment,
                'created_at': review.created_at.isoformat(),
                'likes': review.likes or 0,
                'dislikes': review.dislikes or 0,
                'user_token': review.user_token,  # ✅ Возвращаем как есть
                'device_fingerprint': review.device_fingerprint,  # ✅ Возвращаем как есть
                'user_ratings': review.user_ratings or {}
            }
            reviews_data.append(review_data)

        # print(f"✅ Возвращаем {len(reviews_data)} отзывов")
        # for i, rd in enumerate(reviews_data[:3]):
        #     print(f"  📤 Отзыв {i+1}: id={rd['id']}, user_token='{rd['user_token']}'")

        # Логируем токены для отладки
        for i, rd in enumerate(reviews_data[:5]):
            print(
                f"  📤 Отзыв {i + 1}: id={rd['id']}, user_token='{rd['user_token']}', device_fingerprint='{rd['device_fingerprint']}'")

        return jsonify(reviews_data)

    except Exception as e:
        print(f"❌ Ошибка при получении отзывов: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/reviews/<int:review_id>/rate', methods=['POST'])
def handle_review_rating(review_id):
    try:
        data = request.get_json()
        print(f"=== ОБРАБОТКА ОЦЕНКИ ОТЗЫВА ===")
        print(f"Полученные данные: {data}")

        # Поддерживаем оба формата для обратной совместимости
        action = data.get('action')
        user_token = data.get('user_token')

        if not user_token:
            return jsonify({'error': 'User token required'}), 400

        # Находим отзыв
        review = Review.query.get(review_id)
        if not review:
            return jsonify({'error': 'Review not found'}), 404

        # Инициализируем user_ratings если нет
        if not review.user_ratings:
            review.user_ratings = {}

        # Получаем текущую оценку пользователя
        current_user_rating = review.user_ratings.get(user_token)
        print(f"Текущая оценка пользователя в БД: {current_user_rating}")

        new_likes = review.likes
        new_dislikes = review.dislikes
        new_user_rating = None

        # УПРОЩЕННАЯ ЛОГИКА: отправка like/dislike переключает оценку
        if action == 'like':
            if current_user_rating == 'like':
                # Снимаем лайк
                new_likes = max(0, review.likes - 1)
                if user_token in review.user_ratings:
                    del review.user_ratings[user_token]
                new_user_rating = None
                print("Лайк снят")
            else:
                # Ставим лайк (если был дизлайк - меняем)
                if current_user_rating == 'dislike':
                    new_dislikes = max(0, review.dislikes - 1)
                new_likes = review.likes + 1
                review.user_ratings[user_token] = 'like'
                new_user_rating = 'like'
                print("Лайк поставлен или изменен с дизлайка")

        elif action == 'dislike':
            if current_user_rating == 'dislike':
                # Снимаем дизлайк
                new_dislikes = max(0, review.dislikes - 1)
                if user_token in review.user_ratings:
                    del review.user_ratings[user_token]
                new_user_rating = None
                print("Дизлайк снят")
            else:
                # Ставим дизлайк (если был лайк - меняем)
                if current_user_rating == 'like':
                    new_likes = max(0, review.likes - 1)
                new_dislikes = review.dislikes + 1
                review.user_ratings[user_token] = 'dislike'
                new_user_rating = 'dislike'
                print("Дизлайк поставлен или изменен с лайка")

        else:
            return jsonify({'error': 'Invalid action. Use "like" or "dislike"'}), 400

        # Обновляем счетчики
        review.likes = new_likes
        review.dislikes = new_dislikes

        # Помечаем user_ratings как измененное поле
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(review, "user_ratings")

        # Сохраняем в БД
        db.session.commit()

        # Обновляем объект из БД
        db.session.refresh(review)

        print(f"Результат: лайки={review.likes}, дизлайки={review.dislikes}, user_rating={review.user_ratings.get(user_token)}")
        print("===============================")

        return jsonify({
            'likes': review.likes,
            'dislikes': review.dislikes,
            'user_rating': review.user_ratings.get(user_token),
            'user_ratings': review.user_ratings or {}
        })

    except Exception as e:
        db.session.rollback()
        print(f"Ошибка в handle_review_rating: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

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
    try:
        data = request.get_json()
        print(f"Updating review {review_id} with data: {data}")

        review = Review.query.get_or_404(review_id)

        # Проверяем обязательные поля
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        user_token = data.get('user_token')
        if not user_token:
            return jsonify({'error': 'User token required'}), 400

        # Проверяем права на редактирование
        if review.user_token != user_token and not review.user_token.startswith('legacy_token_'):
            return jsonify({'error': 'Permission denied'}), 403

        # Обновляем поля
        if 'rating' in data:
            review.rating = data['rating']
        if 'comment' in data:
            review.comment = data['comment']

        review.updated_at = datetime.now(timezone.utc)
        db.session.commit()

        return jsonify({
            'message': 'Review updated successfully',
            'review': {
                'id': review.id,
                'rating': review.rating,
                'comment': review.comment,
                'updated_at': review.updated_at.isoformat()
            }
        })

    except Exception as e:
        db.session.rollback()
        print(f"Error updating review: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/reviews', methods=['POST'])
def create_review():
    if request.method == 'GET':
        restaurant_id = request.args.get('restaurant_id')
        if not restaurant_id:
            return jsonify({'error': 'restaurant_id is required'}), 400

        reviews = Review.query.filter_by(restaurant_id=restaurant_id).order_by(Review.created_at.desc()).all()
        reviews_data = [{
            'id': review.id,
            'username': review.username,
            'rating': review.rating,
            'comment': review.comment,
            'created_at': review.created_at.isoformat(),
            'likes': review.likes or 0,
            'dislikes': review.dislikes or 0,
            'user_token': review.user_token,  # ✅ Добавляем
            'device_fingerprint': review.device_fingerprint,  # ✅ Добавляем
            'user_ratings': review.user_ratings or {}
        } for review in reviews]

        return jsonify(reviews_data)

    elif request.method == 'POST':
        try:
            data = request.get_json()
            print("=== СОЗДАНИЕ ОТЗЫВА ===")
            print("Полные данные от клиента:", data)

            if not data:
                return jsonify({'error': 'No data provided'}), 400

            # Проверяем обязательные поля
            required_fields = ['restaurant_id', 'username', 'rating']
            missing_fields = [field for field in required_fields if field not in data]

            if missing_fields:
                return jsonify({'error': f'Missing required fields: {missing_fields}'}), 400

            # Проверяем рейтинг
            rating = int(data['rating'])
            if rating < 1 or rating > 5:
                return jsonify({'error': 'Rating must be between 1 and 5'}), 400

            # Извлекаем токены
            user_token = data.get('user_token')
            device_fingerprint = data.get('device_fingerprint')
            restaurant_id = data['restaurant_id']

            # 🔥 ВАЖНОЕ ИЗМЕНЕНИЕ: Проверяем лимит отзывов для КОНКРЕТНОГО ресторана
            if not check_review_limit_per_restaurant(user_token, restaurant_id):
                return jsonify({
                    'error': f'Вы уже оставляли отзыв для этого заведения сегодня. Следующий отзыв можно будет оставить через 24 часа.'
                }), 429

            # Создаем отзыв
            review = Review(
                restaurant_id=restaurant_id,
                username=data['username'],
                rating=rating,
                comment=data.get('comment', ''),
                user_token=user_token,
                device_fingerprint=device_fingerprint,
                ip_address=request.remote_addr,
                likes=0,
                dislikes=0,
                user_ratings={}
            )

            print(f"🔍 ПЕРЕД СОХРАНЕНИЕМ:")
            print(f"   user_token: '{review.user_token}'")
            print(f"   device_fingerprint: '{review.device_fingerprint}'")

            # Сохраняем в БД
            db.session.add(review)
            db.session.commit()

            # ОБНОВЛЯЕМ объект из БД
            db.session.refresh(review)

            # Обновляем статистику ресторана
            update_restaurant_stats(restaurant_id)
            # ВАЖНО: Возвращаем ВСЕ поля
            response_data = {
                'success': True,
                'message': 'Review added successfully',
                'review': {
                    'id': review.id,
                    'restaurant_id': review.restaurant_id,
                    'username': review.username,
                    'rating': review.rating,
                    'comment': review.comment,
                    'created_at': review.created_at.isoformat(),
                    'likes': review.likes,
                    'dislikes': review.dislikes,
                    'user_token': review.user_token,
                    'device_fingerprint': review.device_fingerprint,
                    'user_ratings': review.user_ratings
                }
            }
            print("✅ Отправляем ответ клиенту:", response_data)
            return jsonify(response_data), 201

        except Exception as e:
            print(f"❌ Ошибка при создании отзыва: {str(e)}")
            import traceback
            traceback.print_exc()
            db.session.rollback()
            return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/debug_current_endpoint', methods=['POST'])
def debug_current_endpoint():
    """Проверка какой endpoint сейчас активен"""
    print("=== DEBUG: ТЕКУЩИЙ ENDPOINT ВЫЗВАН ===")
    data = request.get_json()
    print("Данные:", data)

    # Создаем тестовый отзыв
    review = Review(
        restaurant_id=data['restaurant_id'],
        username=data['username'],
        rating=data['rating'],
        comment=data.get('comment', ''),
        user_token=data['user_token'],
        device_fingerprint=data['device_fingerprint'],
        ip_address=request.remote_addr
    )

    db.session.add(review)
    db.session.commit()
    db.session.refresh(review)

    return jsonify({
        'success': True,
        'endpoint': 'debug_current_endpoint',
        'review': {
            'id': review.id,
            'user_token': review.user_token,
            'device_fingerprint': review.device_fingerprint
        }
    })

@app.route('/api/fix_legacy_reviews', methods=['POST'])
def fix_legacy_reviews():
    """Исправление старых отзывов без user_token"""
    try:
        reviews = Review.query.filter(Review.user_token.is_(None)).all()

        for review in reviews:
            review.user_token = f'legacy_token_{review.id}'
            review.device_fingerprint = f'legacy_device_{review.id}'

        db.session.commit()
        return jsonify({'message': f'Fixed {len(reviews)} legacy reviews'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/migrate_legacy_reviews', methods=['POST'])
def migrate_legacy_reviews():
    """Миграция legacy отзывов ТОЛЬКО для текущего пользователя"""
    try:
        data = request.get_json()
        user_token = data.get('user_token')
        device_fingerprint = data.get('device_fingerprint')

        if not user_token or not device_fingerprint:
            return jsonify({'error': 'User token and device fingerprint required'}), 400

        # Находим legacy отзывы для текущего пользователя (по IP или другим признакам)
        # Например, можно мигрировать отзывы с определенного IP
        user_ip = request.remote_addr

        # Ищем legacy отзывы с текущего IP
        legacy_reviews = Review.query.filter(
            (Review.user_token.startswith('legacy_token_')) &
            (Review.ip_address == user_ip)
        ).all()

        migrated_count = 0
        for review in legacy_reviews:
            # Заменяем legacy токены на реальные
            review.user_token = user_token
            review.device_fingerprint = device_fingerprint
            migrated_count += 1

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Migrated {migrated_count} legacy reviews',
            'migrated_count': migrated_count
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/reviews')
def debug_review(review_id):
    """Отладочная информация по отзыву"""
    try:
        review = Review.query.get(review_id)
        if not review:
            return jsonify({'error': 'Review not found'}), 404

        return jsonify({
            'id': review.id,
            'username': review.username,
            'user_token': review.user_token,
            'device_fingerprint': review.device_fingerprint,
            'created_at': review.created_at.isoformat(),
            'ip_address': review.ip_address
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test_review_creation', methods=['POST'])
def test_review_creation():
    """Тестовое создание отзыва для отладки"""
    try:
        data = request.get_json()
        print("=== ТЕСТОВОЕ СОЗДАНИЕ ОТЗЫВА ===")
        print("Данные:", data)

        # Создаем тестовый отзыв
        review = Review(
            restaurant_id=data['restaurant_id'],
            username=data['username'],
            rating=data['rating'],
            comment=data.get('comment', ''),
            user_token=data['user_token'],
            device_fingerprint=data['device_fingerprint'],
            ip_address=request.remote_addr,
            likes=0,
            dislikes=0,
            user_ratings={}
        )

        print(f"Перед сохранением - user_token: '{review.user_token}'")
        print(f"Перед сохранением - device_fingerprint: '{review.device_fingerprint}'")

        db.session.add(review)
        db.session.commit()
        db.session.refresh(review)

        print(f"После сохранения - user_token: '{review.user_token}'")
        print(f"После сохранения - device_fingerprint: '{review.device_fingerprint}'")

        # Возвращаем полные данные
        return jsonify({
            'success': True,
            'review': {
                'id': review.id,
                'username': review.username,
                'rating': review.rating,
                'comment': review.comment,
                'created_at': review.created_at.isoformat(),
                'user_token': review.user_token,
                'device_fingerprint': review.device_fingerprint,
                'likes': review.likes,
                'dislikes': review.dislikes,
                'user_ratings': review.user_ratings
            }
        })

    except Exception as e:
        print(f"Ошибка: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/review/<int:review_id>')
def debug_review_endpoint(review_id):
    """Endpoint для отладки отзыва"""
    debug_review(review_id)
    return jsonify({'message': 'Check server logs for debug info'})

@app.route('/api/test_simple_update', methods=['PUT'])
def test_simple_update():
    """Простой тестовый endpoint"""
    try:
        data = request.get_json()
        print("Тестовый запрос получен:", data)
        return jsonify({
            'success': True,
            'message': 'Тест успешен',
            'received_data': data,
            'test': 'Это тестовый ответ'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/reviews/<int:review_id>', methods=['DELETE'])
def delete_review(review_id):
    try:
        data = request.get_json()
        print(f"=== УДАЛЕНИЕ ОТЗЫВА {review_id} ===")
        print(f"Данные: {data}")

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        user_token = data.get('user_token')
        device_fingerprint = data.get('device_fingerprint')

        if not user_token or not device_fingerprint:
            return jsonify({'error': 'User token and device fingerprint required'}), 400

        # Находим отзыв
        review = Review.query.get(review_id)
        if not review:
            return jsonify({'error': 'Review not found'}), 404

        print(f"User token в отзыве: {review.user_token}")
        print(f"User token из запроса: {user_token}")

        # Проверяем права на удаление
        if not review.user_token or review.user_token != user_token:
            print("Ошибка: несовпадение user_token")
            return jsonify({'error': 'Permission denied - user token mismatch'}), 403

        # Проверяем время удаления (6 часов)
        now_utc = datetime.utcnow()
        if review.created_at.tzinfo is not None:
            created_at_naive = review.created_at.replace(tzinfo=None)
        else:
            created_at_naive = review.created_at

        time_diff = now_utc - created_at_naive
        hours_diff = time_diff.total_seconds() / 3600

        print(f"Прошло времени с создания: {hours_diff:.2f} часов")

        if hours_diff > 6:
            print("Ошибка: время удаления истекло")
            return jsonify({'error': 'Deletion time expired (6 hours limit)'}), 403

        # Сохраняем restaurant_id для обновления статистики
        restaurant_id = review.restaurant_id

        # Удаляем отзыв
        db.session.delete(review)
        db.session.commit()

        # Обновляем статистику ресторана
        update_restaurant_stats(restaurant_id)

        print("Отзыв успешно удален")
        return jsonify({
            'message': 'Review deleted successfully',
            'restaurant_id': restaurant_id
        })

    except Exception as e:
        db.session.rollback()
        print(f"Ошибка при удалении отзыва: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500


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

def migrate_review_table():
    """Миграция таблицы review - добавление новых столбцов без потери данных"""
    try:
        # Подключаемся к базе данных
        conn = sqlite3.connect('instance/database.db')
        cursor = conn.cursor()

        # Проверяем существование таблицы
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='review'")
        table_exists = cursor.fetchone()

        if not table_exists:
            print("Таблица review не существует. Создаем новую...")
            cursor.execute("""
                CREATE TABLE review (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    restaurant_id VARCHAR(50) NOT NULL,
                    username VARCHAR(100) NOT NULL,
                    rating INTEGER NOT NULL,
                    comment TEXT,
                    created_at DATETIME,
                    updated_at DATETIME,
                    likes INTEGER DEFAULT 0,
                    dislikes INTEGER DEFAULT 0,
                    user_token VARCHAR(255),
                    device_fingerprint VARCHAR(255),
                    ip_address VARCHAR(45),
                    user_ratings TEXT DEFAULT '{}'
                )
            """)
            print("Таблица review создана успешно!")
            conn.commit()
            conn.close()
            return

        print("Таблица review существует. Начинаем миграцию...")

        # Проверяем существующие столбцы
        cursor.execute("PRAGMA table_info(review)")
        columns = [column[1] for column in cursor.fetchall()]

        # Добавляем отсутствующие колонки
        new_columns = [
            ('updated_at', 'DATETIME'),
            ('user_token', 'VARCHAR(255)'),
            ('device_fingerprint', 'VARCHAR(255)'),
            ('ip_address', 'VARCHAR(45)'),
            ('user_ratings', 'TEXT DEFAULT "{}"')
        ]

        for column_name, column_type in new_columns:
            if column_name not in columns:
                print(f"Добавляем колонку {column_name}...")
                cursor.execute(f"ALTER TABLE review ADD COLUMN {column_name} {column_type}")

        # Обновляем значения для новых колонок
        cursor.execute("UPDATE review SET user_ratings = '{}' WHERE user_ratings IS NULL")
        cursor.execute("UPDATE review SET likes = 0 WHERE likes IS NULL")
        cursor.execute("UPDATE review SET dislikes = 0 WHERE dislikes IS NULL")

        conn.commit()
        print("Миграция таблицы review завершена успешно!")

    except Exception as e:
        print(f"Ошибка при миграции: {e}")
        conn.rollback()
        raise e
    finally:
        conn.close()

@app.route('/api/reviews/<int:review_id>/migrate', methods=['POST'])
def migrate_review(review_id):
    """Миграция legacy отзыва на текущего пользователя"""
    try:
        data = request.get_json()
        user_token = data.get('user_token')
        device_fingerprint = data.get('device_fingerprint')

        if not user_token or not device_fingerprint:
            return jsonify({'error': 'User token and device fingerprint required'}), 400

        # Находим отзыв
        review = Review.query.get(review_id)
        if not review:
            return jsonify({'error': 'Review not found'}), 404

        # Проверяем что это legacy отзыв
        if not review.user_token or not review.user_token.startswith('legacy_token_'):
            return jsonify({'error': 'Not a legacy review'}), 400

        # Дополнительные проверки можно добавить здесь
        # Например, проверка по IP, username и т.д.

        # Мигрируем отзыв
        review.user_token = user_token
        review.device_fingerprint = device_fingerprint

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Review migrated successfully',
            'review': {
                'id': review.id,
                'user_token': review.user_token,
                'device_fingerprint': review.device_fingerprint
            }
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Получение секретного ключа из базы данных и настройка Flask-приложения
app.config['SECRET_KEY'] = get_secret('SECRET_KEY')

with app.app_context():
    db.create_all()

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

@app.route("/test", methods=['GET', 'POST'])
def test():
    return render_template("ЛичныеСтраницы/test.html", title="Городской гид")

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
def restaurant():
    print(url_for("restaurant"))
    restaurants = Place.query.filter_by(category='Ресторан').all()
    return render_template("Restaurant.html",
                           title="Рестораны",
                           restaurants=restaurants)

@app.route('/Restaurant/<int:id>')
def restaurant_page(id):
    place = Place.query.get_or_404(id)
    template_map = {
        1: 'ЛичныеСтраницы/Brewmen.html',
        2: 'ЛичныеСтраницы/lambs.html',
        3: 'ЛичныеСтраницы/Gurmetto.html',
        4: 'ЛичныеСтраницы/PizzaFactory.html',
        5: 'ЛичныеСтраницы/Иль-де-Франс.html',
        6: 'ЛичныеСтраницы/Пряник.html',
        7: 'ЛичныеСтраницы/Marusya.html',
        8: 'ЛичныеСтраницы/Проун.html',
        9: 'ЛичныеСтраницы/ПхалиХинкали.html',
        10: 'ЛичныеСтраницы/Мамонт.html',
        11: 'ЛичныеСтраницы/География.html',
        12: 'ЛичныеСтраницы/Токио-City.html',
        13: 'ЛичныеСтраницы/Чародейка.html',
        14: 'ЛичныеСтраницы/Napoli.html',
        15: 'ЛичныеСтраницы/Legenda.html',
        16: 'ЛичныеСтраницы/Сытый гусь.html',
        17: 'ЛичныеСтраницы/Дом Берга.html',
        18: 'ЛичныеСтраницы/Рестобар Кружечный Двор.html',
        19: 'ЛичныеСтраницы/Bistro Palazzo 5.html',
        20: 'ЛичныеСтраницы/Фрегат Флагман.html',
        21: 'ЛичныеСтраницы/Тепло траттория.html',
        22: 'ЛичныеСтраницы/Сказка.html',
        23: 'ЛичныеСтраницы/Чайхана Сказка.html',
        24: 'ЛичныеСтраницы/Наffига козе баян?!.html',
        25: 'ЛичныеСтраницы/Хурма.html',
        26: 'ЛичныеСтраницы/My Kitchen.html',
        27: 'ЛичныеСтраницы/Фазенда.html',
        28: 'ЛичныеСтраницы/Mbur.html',
        29: 'ЛичныеСтраницы/На Солнце.html',
        30: 'ЛичныеСтраницы/Шаурpoint.html',
        31: 'ЛичныеСтраницы/Дорадо.html',
        32: 'ЛичныеСтраницы/Лимузин.html',
        33: 'ЛичныеСтраницы/Персона.html',
        34: 'ЛичныеСтраницы/Бруклин.html',
        35: 'ЛичныеСтраницы/Изюм.html',
        36: 'ЛичныеСтраницы/Mycroft.html',
        37: 'ЛичныеСтраницы/Хлебник.html',
        38: 'ЛичныеСтраницы/Время Ч.html',
        39: 'ЛичныеСтраницы/МамаСушиПицца.html',
        40: 'ЛичныеСтраницы/Ромитто.html',
        41: 'ЛичныеСтраницы/Колобок.html',
        42: 'ЛичныеСтраницы/Старик Хинкалыч.html',
        43: 'ЛичныеСтраницы/Садко.html',
        44: 'ЛичныеСтраницы/Юрьевское Подворье.html',
        45: 'ЛичныеСтраницы/Шкипер.html',
        46: 'ЛичныеСтраницы/Диез.html',
        47: 'ЛичныеСтраницы/Cafe Le Chocolat.html',
        48: 'ЛичныеСтраницы/Гипер Лента.html',
        49: 'ЛичныеСтраницы/ВкусВилл.html',
        50: 'ЛичныеСтраницы/Дикси.html',
        51: 'ЛичныеСтраницы/Дикси1.html',
        52: 'ЛичныеСтраницы/Дикси2.html',
        53: 'ЛичныеСтраницы/Перекрёсток.html',
        54: 'ЛичныеСтраницы/Магнит.html',
        55: 'ЛичныеСтраницы/Магнит1.html',
        56: 'ЛичныеСтраницы/Магнит2.html',
        57: 'ЛичныеСтраницы/Пятёрочка.html',
        58: 'ЛичныеСтраницы/Пятёрочка1.html',
        59: 'ЛичныеСтраницы/Осень.html',
        60: 'ЛичныеСтраницы/Осень1.html',
        61: 'ЛичныеСтраницы/Осень2.html',
        62: 'ЛичныеСтраницы/Осень3.html',
        63: 'ЛичныеСтраницы/Осень4.html',
        64: 'ЛичныеСтраницы/Осень5.html',
        65: 'ЛичныеСтраницы/Верный.html',
        66: 'ЛичныеСтраницы/Верный1.html',
        67: 'ЛичныеСтраницы/Десяточка.html',
        68: 'ЛичныеСтраницы/Градусы.html',
        69: 'ЛичныеСтраницы/Магазинъ.html',
        70: 'ЛичныеСтраницы/Светофор.html',
        71: 'ЛичныеСтраницы/Продукты 24.html',
        72: 'ЛичныеСтраницы/Музей народного деревянного зодчества Витославлицы.html',
        73: 'ЛичныеСтраницы/Новгородский кремль.html',
        74: 'ЛичныеСтраницы/Центр музыкальных древностей В.И. Поветкина.html',
        75: 'ЛичныеСтраницы/Киномузей Валерия Рубцова.html',
        76: 'ЛичныеСтраницы/Новгородский государственный объединенный музей-заповедник.html',
        77: 'ЛичныеСтраницы/Музей изобразительных искусств.html',
        78: 'ЛичныеСтраницы/Музейный цех фарфора.html',
        79: 'ЛичныеСтраницы/Государственный музей художественной культуры Новгородской земли.html',
        80: 'ЛичныеСтраницы/Владычная палата.html',
        81: 'ЛичныеСтраницы/Мастерская-музей реалистической живописи Александра Варенцова.html',
        82: 'ЛичныеСтраницы/Музей письменности.html',
        83: 'ЛичныеСтраницы/Детский музейный центр.html',
        84: 'ЛичныеСтраницы/Алексеевская Белая башня.html',
        85: 'ЛичныеСтраницы/Зал воинской славы.html',
        86: 'ЛичныеСтраницы/Музей Утюга.html',
        87: 'ЛичныеСтраницы/Новгородский музей-заповедник.html',
        88: 'ЛичныеСтраницы/Центр противопожарной пропаганды и общественных связей.html',
        89: 'ЛичныеСтраницы/Стены и башни Новгородского кремля.html',
        90: 'ЛичныеСтраницы/Лекторий.html',
        91: 'ЛичныеСтраницы/Дирекция Новгородского государственного объединённого музея-заповедника.html',
        92: 'ЛичныеСтраницы/Усадебный дом А.А. Орловой-Чесменской.html',
        93: 'ЛичныеСтраницы/Музей истории органов внутренних дел Новгородской области культурного центра УМВД России по Новгородской области.html',
        94: 'ЛичныеСтраницы/Новгородский областной академический театр драмы имени Достоевского.html',
        95: 'ЛичныеСтраницы/Театр для детей и молодежи Малый.html',
        96: 'ЛичныеСтраницы/Молодежная библиотека.html',
        97: 'ЛичныеСтраницы/Библиотечный центр Читай-город.html',
        98: 'ЛичныеСтраницы/Веряжский парк.html',
        99: 'ЛичныеСтраницы/Сквер Кочетова.html',
        100: 'ЛичныеСтраницы/Сквер Минутка.html',
        101: 'ЛичныеСтраницы/Сквер Защитников Отечества.html',
        102: 'ЛичныеСтраницы/Мираж Синема.html',
        103: 'ЛичныеСтраницы/Новгород.html',
        104: 'ЛичныеСтраницы/Мультимедийный центр Россия.html',
        105: 'ЛичныеСтраницы/Планетарий Орион.html',
        106: 'ЛичныеСтраницы/Спортплощадка.html',
        107: 'ЛичныеСтраницы/Карелинн.html',
        108: 'ЛичныеСтраницы/Церковь Спаса Преображения на Ильине улице.html',
        109: 'ЛичныеСтраницы/Церковь Успения Пресвятой Богородицы на Волотовом поле.html',
        110: 'ЛичныеСтраницы/Вишневый Рояль.html',
    }
    template = template_map.get(id, 'default_restaurant.html')
    return render_template(template, place=place)


@app.route('/restaurants')
def restaurants_page():
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Увеличили с 5 до 10

    # Получаем рестораны из таблицы Place с категорией 'Ресторан'
    total_restaurants = Place.query.filter_by(category='Ресторан').count()
    total_pages = math.ceil(total_restaurants / per_page)

    # Получаем рестораны для текущей страницы
    restaurants = Place.query.filter_by(category='Ресторан') \
        .offset((page - 1) * per_page) \
        .limit(per_page) \
        .all()

    # Если это AJAX запрос, возвращаем JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        restaurants_data = []
        for restaurant in restaurants:
            restaurants_data.append({
                'id': restaurant.id,
                'title': restaurant.title,
                'description': restaurant.description,
                'telephone': restaurant.telephone,
                'address': restaurant.address,
                'image_path': restaurant.image_path
            })

        return jsonify({
            'restaurants': restaurants_data,
            'current_page': page,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_prev': page > 1
        })

    # Обычный запрос - рендерим полную страницу
    return render_template('Restaurant.html',
                           restaurants=restaurants,
                           current_page=page,
                           total_pages=total_pages,
                           title="Рестораны")

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
@app.route('/Restaurant/Brewmen')
def Brewmen():
    place = Place.query.get_or_404(1)
    return render_template('ЛичныеСтраницы/Brewmen.html', place=place)

@app.route('/Restaurant/Барашки')
def lambs():
    place = Place.query.get_or_404(2)  # ID Барашек
    return render_template('ЛичныеСтраницы/lambs.html', place=place)

@app.route('/Restaurant/Гурметто')
def Gurmetto():
    place = Place.query.get_or_404(3)
    return render_template('ЛичныеСтраницы/Gurmetto.html')

@app.route('/Restaurant/ПиццаФабрика')
def PizzaFactory():
    place = Place.query.get_or_404(4)
    return render_template('ЛичныеСтраницы/PizzaFactory.html')

@app.route('/Restaurant/Ile_de_France')
def IleDeFrance():
    place = Place.query.get_or_404(5)
    return render_template('ЛичныеСтраницы/IleDeFrance.html')

@app.route('/Restaurant/SpiceCake')
def SpiceCake():
    place = Place.query.get_or_404(6)
    return render_template('ЛичныеСтраницы/SpiceCake.html')

@app.route('/Restaurant/Marusya')
def Marusya():
    place = Place.query.get_or_404(7)
    return render_template('ЛичныеСтраницы/Marusya.html')

@app.route('/Restaurant/Proun')
def Proun():
    place = Place.query.get_or_404(8)
    return render_template('ЛичныеСтраницы/Proun.html')

@app.route('/Restaurant/PhaliHinkali')
def PhaliHinkali():
    place = Place.query.get_or_404(9)
    return render_template('ЛичныеСтраницы/PhaliHinkali.html')
@app.route('/Restaurant/Mammoth')
def Mammoth():
    place = Place.query.get_or_404(10)
    return render_template('ЛичныеСтраницы/Mammoth.html')

@app.route('/Restaurant/Geography')
def Geography():
    place = Place.query.get_or_404(11)
    return render_template('ЛичныеСтраницы/Geography.html')

@app.route('/Restaurant/Tokyo_City')
def TokyoCity():
    place = Place.query.get_or_404(12)
    return render_template('ЛичныеСтраницы/TokyoCity.html')

@app.route('/Restaurant/Чародейка')
def Enchantress():
    place = Place.query.get_or_404(13)
    return render_template('ЛичныеСтраницы/Enchantress.html')

@app.route('/Restaurant/Napoli')
def Napoli():
    place = Place.query.get_or_404(14)
    return render_template('ЛичныеСтраницы/Napoli.html')

@app.route('/Restaurant/Legenda')
def Legenda():
    place = Place.query.get_or_404(15)
    return render_template('ЛичныеСтраницы/Legenda.html')

@app.route('/Restaurant/Well_fed_goose')
def WellFedGoose():
    place = Place.query.get_or_404(16)
    return render_template('ЛичныеСтраницы/WellFedGoose.html')

@app.route('/Restaurant/Bergs_House')
def BergsHouse():
    place = Place.query.get_or_404(17)
    return render_template('ЛичныеСтраницы/BergsHouse.html')

@app.route('/Restaurant/Restobar_circular_Courtyard')
def RestobarCircularCourtyard():
    place = Place.query.get_or_404(18)
    return render_template('ЛичныеСтраницы/RestobarCircularCourtyard.html')

@app.route('/Restaurant/Bistro_Palazzo_5')
def BistroPalazzo5():
    place = Place.query.get_or_404(19)
    return render_template('ЛичныеСтраницы/BistroPalazzo5.html')

@app.route('/Restaurant/Flagship_Frigate')
def FlagshipFrigate():
    place = Place.query.get_or_404(20)
    return render_template('ЛичныеСтраницы/FlagshipFrigate.html')

@app.route('/Restaurant/Teplo_trategory')
def TeploTrategory():
    place = Place.query.get_or_404(21)
    return render_template('ЛичныеСтраницы/TeploTrategory.html')

@app.route('/Restaurant/FairyTale')
def FairyTale():
    place = Place.query.get_or_404(22)
    return render_template('ЛичныеСтраницы/FairyTale.html')

@app.route('/Restaurant/FairyTale_Teahouse')
def FairyTaleTeahouse():
    place = Place.query.get_or_404(23)
    return render_template('ЛичныеСтраницы/FairyTaleTeahouse.html')

@app.route('/Restaurant/Naffiga_koze_bayan')
def NaffigaKozeBayan():
    place = Place.query.get_or_404(24)
    return render_template('ЛичныеСтраницы/NaffigaKozeBayan.html')

@app.route('/Restaurant/Persimmon')
def Persimmon():
    place = Place.query.get_or_404(25)
    return render_template('ЛичныеСтраницы/Persimmon.html')

@app.route('/Restaurant/My Kitchen')
def MyKitchen():
    place = Place.query.get_or_404(26)
    return render_template('ЛичныеСтраницы/MyKitchen.html')

@app.route('/Restaurant/Hacienda')
def Hacienda():
    place = Place.query.get_or_404(27)
    return render_template('ЛичныеСтраницы/Hacienda.html')

@app.route('/Restaurant/Mbur')
def Mbur():
    place = Place.query.get_or_404(28)
    return render_template('ЛичныеСтраницы/Mbur.html')

@app.route('/Restaurant/On_sunce')
def OnSunce():
    place = Place.query.get_or_404(29)
    return render_template('ЛичныеСтраницы/OnSunce.html')

@app.route('/Restaurant/Shauрpoint')
def Shauрpoint():
    place = Place.query.get_or_404(30)
    return render_template('ЛичныеСтраницы/Shauрpoint.html')

@app.route('/Restaurant/Dorado')
def Dorado():
    place = Place.query.get_or_404(31)
    return render_template('ЛичныеСтраницы/Dorado.html')

@app.route('/Restaurant/limo')
def limo():
    place = Place.query.get_or_404(32)
    return render_template('ЛичныеСтраницы/limo.html')

@app.route('/Restaurant/Person')
def Person():
    place = Place.query.get_or_404(33)
    return render_template('ЛичныеСтраницы/Person.html')

@app.route('/Restaurant/Brooklyn')
def Brooklyn():
    place = Place.query.get_or_404(34)
    return render_template('ЛичныеСтраницы/Brooklyn.html')

@app.route('/Restaurant/Raisin')
def Raisin():
    place = Place.query.get_or_404(35)
    return render_template('ЛичныеСтраницы/Raisin.html')

@app.route('/Restaurant/Mycroft')
def Mycroft():
    place = Place.query.get_or_404(36)
    return render_template('ЛичныеСтраницы/Mycroft.html')
@app.route('/Restaurant/Baker')
def Baker():
    place = Place.query.get_or_404(37)
    return render_template('ЛичныеСтраницы/Baker.html')

@app.route('/Restaurant/TIME_H')
def TIME_H():
    place = Place.query.get_or_404(38)
    return render_template('ЛичныеСтраницы/TIME_H.html')

@app.route('/Restaurant/MamaSushiPitsa')
def MamaSushiPitsa():
    place = Place.query.get_or_404(39)
    return render_template('ЛичныеСтраницы/MamaSushiPitsa.html')

@app.route('/Restaurant/Romitto')
def Romitto():
    place = Place.query.get_or_404(40)
    return render_template('ЛичныеСтраницы/Romitto.html')

@app.route('/Restaurant/Kolobok')
def Kolobok():
    place = Place.query.get_or_404(41)
    return render_template('ЛичныеСтраницы/Kolobok.html')

@app.route('/Restaurant/old_Man_hinkalych')
def oldManHinkalych():
    place = Place.query.get_or_404(42)
    return render_template('ЛичныеСтраницы/oldManHinkalych.html')

@app.route('/Restaurant/Sadko')
def Sadko():
    place = Place.query.get_or_404(43)
    return render_template('ЛичныеСтраницы/Sadko.html')

@app.route('/Restaurant/Yuryevskoe_Courtyard')
def YuryevskoeCourtyard():
    place = Place.query.get_or_404(44)
    return render_template('ЛичныеСтраницы/YuryevskoeCourtyard.html')

@app.route('/Restaurant/Skipper')
def Skipper():
    place = Place.query.get_or_404(45)
    return render_template('ЛичныеСтраницы/Skipper.html')

@app.route('/Restaurant/Sharp')
def Sharp():
    place = Place.query.get_or_404(46)
    return render_template('ЛичныеСтраницы/Sharp.html')

@app.route('/Restaurant/Cafe Le Chocolat')
def CafeLeChocolat():
    place = Place.query.get_or_404(47)
    return render_template('ЛичныеСтраницы/CafeLeChocolat.html')

@app.route('/Restaurant/Hyper_lent')
def HyperLent():
    place = Place.query.get_or_404(48)
    return render_template('ЛичныеСтраницы/HyperLent.html')

@app.route('/Restaurant/VkusVille')
def VkusVille():
    place = Place.query.get_or_404(49)
    return render_template('ЛичныеСтраницы/VkusVille.html')

@app.route('/Restaurant/Dixie')
def Dixie():
    place = Place.query.get_or_404(50)
    return render_template('ЛичныеСтраницы/Dixie.html')

@app.route('/Restaurant/Dixie')
def Dixie1():
    place = Place.query.get_or_404(51)
    return render_template('ЛичныеСтраницы/Dixie1.html')

@app.route('/Restaurant/Dixie')
def Dixie2():
    place = Place.query.get_or_404(52)
    return render_template('ЛичныеСтраницы/Dixie2.html')

@app.route('/Restaurant/Crossroad')
def Crossroad():
    place = Place.query.get_or_404(53)
    return render_template('ЛичныеСтраницы/Crossroad.html')

@app.route('/Restaurant/Magnet')
def Magnet():
    place = Place.query.get_or_404(54)
    return render_template('ЛичныеСтраницы/Magnet.html')

@app.route('/Restaurant/Magnet')
def Magnet1():
    place = Place.query.get_or_404(55)
    return render_template('ЛичныеСтраницы/Magnet1.html')

@app.route('/Restaurant/Magnet')
def Magnet2():
    place = Place.query.get_or_404(56)
    return render_template('ЛичныеСтраницы/Magnet2.html')

@app.route('/Restaurant/Pyaterochka')
def Pyaterochka():
    place = Place.query.get_or_404(57)
    return render_template('ЛичныеСтраницы/Pyaterochka.html')

# Добавьте эти обработчики ошибок
@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(408)
@app.errorhandler(409)
@app.errorhandler(410)
@app.errorhandler(429)
@app.errorhandler(500)
@app.errorhandler(502)
@app.errorhandler(503)
@app.errorhandler(504)
def handle_error(error):
    """Универсальный обработчик ошибок"""
    error_code = getattr(error, 'code', 500)
    error_name = get_error_name(error_code)

    # Если это AJAX запрос, возвращаем JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'error': True,
            'code': error_code,
            'name': error_name,
        }), error_code

    # Иначе рендерим HTML страницу
    return render_template('error.html',
                           error_code=error_code,
                           error_name=error_name), error_code


def get_error_name(code):
    """Возвращает название ошибки по коду"""
    error_names = {
        400: "Плохой запрос",
        401: "Не авторизован",
        403: "Запрещено",
        404: "Страница не найдена",
        405: "Метод не разрешен",
        408: "Bed signal",
        409: "Конфликт",
        410: "Удалено",
        429: "Слишком много запросов",
        500: "Внутренняя ошибка сервера",
        502: "Плохой шлюз",
        503: "Сервис недоступен",
        504: "Время ответа шлюза истекло"
    }
    return error_names.get(code, "Неизвестная ошибка")

if __name__ == '__main__':
    with app.app_context():
        check_review_table_structure()
        migrate_review_table()
        db.create_all()
    app.run(debug=True)