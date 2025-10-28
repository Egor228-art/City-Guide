import hashlib
import json
import re
import os

import pytz
import math
import sqlite3

from werkzeug.utils import secure_filename, redirect
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, jsonify, render_template, request, url_for, session, flash
from datetime import datetime, timezone, timedelta
from flask_migrate import Migrate
from functools import wraps
from flask import abort

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
MOSCOW_TZ = pytz.timezone('Europe/Moscow')

db = SQLAlchemy(app)
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

# Роли и их права
# Улучшенная система прав
ROLE_PERMISSIONS = {
    'trainee': {
        'name': 'Стажёр',
        'permissions': [
            'view_dashboard',
            'create_place',
            'create_category',
            'view_stats'
        ]
    },
    'moderator': {
        'name': 'Модератор',
        'permissions': [
            'view_dashboard',
            'create_place', 'edit_place', 'delete_place',
            'create_category', 'edit_category', 'delete_category',
            'edit_review', 'delete_review',
            'manage_trainees',  # Может управлять стажёрами
            'view_stats'
        ]
    },
    'editor': {
        'name': 'Редактор',
        'permissions': [
            'view_dashboard',
            'create_place', 'edit_place', 'delete_place',
            'create_category', 'edit_category', 'delete_category',
            'edit_review', 'delete_review',
            'manage_trainees', 'manage_moderators', 'manage_editors',
            'view_stats',
            'system_settings'
        ]
    },
    'admin': {
        'name': 'Администратор',
        'permissions': ['all']  # Все права
    }
}

def get_role_permissions(role):
    """Получить права для роли"""
    role_permissions = {
        'trainee': ['create_place', 'create_category', 'view_stats'],
        'moderator': ['create_place', 'edit_place', 'delete_place',
                      'create_category', 'edit_category', 'delete_category',
                      'edit_review', 'delete_review', 'manage_trainees', 'view_stats'],
        'editor': ['create_place', 'edit_place', 'delete_place',
                   'create_category', 'edit_category', 'delete_category',
                   'edit_review', 'delete_review', 'manage_trainees', 'manage_moderators',
                   'manage_editors', 'view_stats', 'system_settings'],
        'admin': ['all']
    }

    if role not in role_permissions:
        return []

    permissions = role_permissions[role]
    if 'all' in permissions:
        return ['all']  # Специальный маркер для всех прав
    return permissions

def get_role_display_name(role):
    """Получить отображаемое имя роли"""
    return ROLE_PERMISSIONS.get(role, {}).get('name', role)


def permission_required(permission):
    """Декоратор для проверки прав"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                abort(401)

            user = User.query.filter_by(username=session['username']).first()

            # Admin имеет все права
            if user.role == 'admin':
                return f(*args, **kwargs)

            # Проверяем конкретное право
            user_permissions = get_role_permissions(user.role)
            if permission not in user_permissions and 'all' not in user_permissions:
                return render_template('Error.html', error_code=403), 403

            return f(*args, **kwargs)

        return decorated_function

    return decorator

def role_required(required_permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                abort(401)

            user = User.query.filter_by(username=session['username']).first()
            if not user:
                abort(401)

            # Admin имеет все права
            if user.role == 'admin':
                return f(*args, **kwargs)

            # Проверяем права для роли (ИСПРАВЛЕННАЯ СТРОКА)
            user_permissions = get_role_permissions(user.role)
            if required_permission not in user_permissions and 'all' not in user_permissions:
                return render_template('Error.html', error_code=403), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Конкретные декораторы для удобства
def trainee_required(f):
    return role_required('create_place')(f)

def moderator_required(f):
    return role_required('manage_trainees')(f)

def editor_required(f):
    return role_required('manage_moderators')(f)

# Определяем модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), default='trainee')  # trainee, moderator, editor, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

    @property
    def role_display(self):
        return get_role_display_name(self.role)

    def has_permission(self, permission):
        user_permissions = get_role_permissions(self.role)
        return 'all' in user_permissions or permission in user_permissions

    def can_manage_user(self, target_user):
        if self.id == target_user.id:
            return False
        role_hierarchy = {'trainee': 1, 'moderator': 2, 'editor': 3, 'admin': 4}
        return role_hierarchy.get(self.role, 0) > role_hierarchy.get(target_user.role, 0)

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
    category = db.Column(db.String(50), nullable=False, default='Restaurant')
    category_en = db.Column(db.String(50), nullable=False, default='Restaurant')
    slug = db.Column(db.String(100), unique=True, nullable=True)  # Для английских URL
    latitude = db.Column(db.Float)  # широта для карт
    longitude = db.Column(db.Float)  # долгота для карт
    working_hours = db.Column(db.JSON)  # {"пн-пт": "10:00-22:00", "сб-вс": "11:00-23:00"}
    menu = db.Column(db.Text, default='{}')  # {"category": [{"name": "", "price": ""}]}

    # Словарь для преобразования категорий
    CATEGORY_MAPPING = {
        'Ресторан': 'Restaurant',
        'Кафе': 'Cafe',
        'Магазин': 'Shop',
        'Музей': 'Museum',
        'Театр': 'Theatre',
        'Библиотека': 'Library',
        'Парк': 'Park',
        'Кинотеатр': 'Cinema',
        'Спортплощадка': 'Sports',
        'Церковь': 'Church',
        'Гостиница': 'Hotel',
        'Иконка': 'Icon'
    }

    def __repr__(self):
        return f'<Place {self.title}>'

    def get_menu_dict(self):
        """Безопасное получение меню с проверкой на пустоту"""
        try:
            if self.menu and self.menu.strip():
                menu_data = json.loads(self.menu)
                # 🔥 Проверяем, что меню не пустое
                if menu_data and isinstance(menu_data, dict):
                    # Убираем пустые категории
                    filtered_menu = {}
                    for category, items in menu_data.items():
                        if items and isinstance(items, list) and len(items) > 0:
                            # Убираем пустые items
                            filtered_items = [item for item in items if item.get('name')]
                            if filtered_items:
                                filtered_menu[category] = filtered_items

                    return filtered_menu if filtered_menu else {}
            return {}
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            print(f"Error parsing menu for place {self.id}: {e}")
            return {}

    def has_menu(self):
        """Проверяет, есть ли реальное меню (не пустое)"""
        try:
            if self.menu and self.menu.strip():
                menu_data = json.loads(self.menu)
                # Проверяем что меню не пустое
                if menu_data and isinstance(menu_data, dict):
                    # Проверяем есть ли хотя бы одна категория с items
                    for category, items in menu_data.items():
                        if items and isinstance(items, list) and len(items) > 0:
                            # Проверяем что есть хотя бы один непустой item
                            for item in items:
                                if item.get('name') and item.get('name').strip():
                                    return True
            return False
        except (json.JSONDecodeError, TypeError, ValueError):
            return False

    def get_menu_data(self):
        """Алиас для get_menu_dict"""
        return self.get_menu_dict()

    def get_tags_list(self):
        """Получение тегов в виде списка"""
        if self.tags:
            return [tag.strip() for tag in self.tags.split(',')]
        return []

    def get_working_hours_display(self):
        """Красивое отображение времени работы"""
        try:
            if self.working_hours:
                # Если это уже словарь - используем как есть
                if isinstance(self.working_hours, dict):
                    hours_data = self.working_hours
                else:
                    # Иначе пытаемся распарсить JSON
                    hours_data = json.loads(self.working_hours)

                if hours_data and isinstance(hours_data, dict):
                    # Форматируем красиво с переносами строк
                    result = []
                    for days, hours in hours_data.items():
                        result.append(f"{days}: {hours}")
                    return "<br>".join(result)
            return "Время работы не указано"
        except Exception as e:
            print(f"Ошибка при форматировании времени работы: {e}")
            return "Время работы не указано"

    def get_working_hours_safe(self):
        """Безопасное получение времени работы"""
        try:
            if self.working_hours:
                if isinstance(self.working_hours, dict):
                    return self.working_hours
                return json.loads(self.working_hours)
            return {}
        except:
            return {}

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
    user_ratings = db.Column(db.JSON, default=dict)

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
    """Обновление статистики ресторана на основе отзывов"""
    print(f"Обновление статистики для ресторана {restaurant_id}")

    reviews = Review.query.filter_by(restaurant_id=restaurant_id).all()
    print(f"Найдено отзывов: {len(reviews)}")

    if not reviews:
        # Если нет отзывов, устанавливаем значения по умолчанию
        restaurant = Restaurant.query.get(restaurant_id)
        if restaurant:
            restaurant.total_rating = 0.0
            restaurant.review_count = 0
            restaurant.last_updated = datetime.utcnow()
            db.session.commit()
            print(f"Установлены значения по умолчанию для {restaurant_id}")
        return

    total_rating = sum(review.rating for review in reviews)
    review_count = len(reviews)
    average_rating = total_rating / review_count

    print(f"Расчет для {restaurant_id}: отзывов={review_count}, сумма={total_rating}, среднее={average_rating}")

    # Ищем существующий ресторан или создаем новый
    restaurant = Restaurant.query.get(restaurant_id)
    if not restaurant:
        # Получаем название места для нового ресторана
        place = Place.query.get(int(restaurant_id)) if restaurant_id.isdigit() else None
        restaurant_name = place.title if place else f"Place {restaurant_id}"

        restaurant = Restaurant(
            id=restaurant_id,
            name=restaurant_name,
            total_rating=average_rating,
            review_count=review_count
        )
        db.session.add(restaurant)
        print(f"Создан новый ресторан: {restaurant_id} - {restaurant_name}")
    else:
        restaurant.total_rating = average_rating
        restaurant.review_count = review_count
        print(f"Обновлен существующий ресторан: {restaurant_id}")

    restaurant.last_updated = datetime.utcnow()
    db.session.commit()
    print(f"Сохранено в БД: {restaurant_id} - рейтинг {average_rating}, отзывов {review_count}")

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

def advanced_search(query):
    """Умный поиск с запасным вариантом и ДОБАВЛЕННЫМ поиском по категориям"""
    # Сначала пробуем точный поиск
    precise_results = precise_search(query)

    if precise_results.count() > 0:
        print(f"Точный поиск нашел {precise_results.count()} результатов")
        return precise_results

def precise_search(query):
    """Точный поиск с учетом всех слов, ВКЛЮЧАЯ поиск по категориям"""
    search_words = query.strip().lower().split()
    base_query = Place.query.filter(Place.category != 'Иконка')

    if not search_words:
        return base_query

    conditions = []
    for word in search_words:
        if len(word) >= 2:
            pattern = f'%{word}%'

            # Создаем маппинг русских названий категорий для поиска
            category_mapping = {
                'ресторан': 'Ресторан',
                'кафе': 'Кафе',
                'магазин': 'Магазин',
                'музей': 'Музей',
                'театр': 'Театр',
                'библиотека': 'Библиотека',
                'парк': 'Парк',
                'кинотеатр': 'Кинотеатр',
                'спортплощадка': 'Спортплощадка',
                'церковь': 'Церковь',
                'гостиница': 'Гостиница',
                'отель': 'Гостиница',
                'кофейня': 'Кафе',
                'бар': 'Ресторан',
                'пиццерия': 'Ресторан',
                'суши': 'Ресторан',
                'паб': 'Ресторан',
                'бистро': 'Ресторан'
            }

            # СУЩЕСТВУЮЩИЕ условия поиска (название, описание, адрес, теги)
            word_conditions = [
                Place.title.ilike(pattern),
                Place.description.ilike(pattern),
                Place.tags.ilike(pattern),
                Place.address.ilike(pattern),
                Place.telephone.ilike(pattern),
                # ДОБАВЛЯЕМ поиск по категориям
                Place.category.ilike(pattern),
                Place.category_en.ilike(pattern)
            ]

            # ДОБАВЛЯЕМ поиск по маппингу категорий (например, "ресторан" -> категория "Ресторан")
            if word in category_mapping:
                category_ru = category_mapping[word]
                word_conditions.append(Place.category == category_ru)
                print(f"Применен маппинг категории: '{word}' -> '{category_ru}'")

            # Для русских слов добавляем поиск с разным регистром
            if any(cyrillic in word for cyrillic in 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'):
                word_conditions.extend([
                    Place.title.ilike(f'%{word.capitalize()}%'),
                    Place.title.ilike(f'%{word.upper()}%'),
                    Place.address.ilike(f'%{word.capitalize()}%'),
                    Place.address.ilike(f'%{word.upper()}%'),
                    # ДОБАВЛЯЕМ поиск по категориям с разным регистром
                    Place.category.ilike(f'%{word.capitalize()}%'),
                    Place.category.ilike(f'%{word.upper()}%')
                ])

            word_condition = db.or_(*word_conditions)
            conditions.append(word_condition)

    if conditions:
        return base_query.filter(db.and_(*conditions))
    else:
        return base_query.filter(False)



#Админские штуки - НАЧАЛО

@app.route('/admin/api/create-test-data')
def create_test_data():
    """Создание тестовых данных для админ-панели"""
    try:
        # Создаем тестовое место если нет мест
        if Place.query.count() == 0:
            test_place = Place(
                title='Тестовый Ресторан',
                description='Тестовое описание',
                category='Ресторан',
                category_en='restaurant',
                slug='test-restaurant'
            )
            db.session.add(test_place)
            db.session.commit()

        # Создаем тестовые отзывы если нет отзывов
        if Review.query.count() == 0:
            test_review = Review(
                restaurant_id='1',  # ID тестового места
                username='Тестовый Пользователь',
                rating=5,
                comment='Отличное тестовое заведение!',
                user_token='test_token',
                device_fingerprint='test_fingerprint'
            )
            db.session.add(test_review)
            db.session.commit()

        return jsonify({'success': True, 'message': 'Тестовые данные созданы'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/api/debug')
def admin_debug():
    """Отладочный endpoint для проверки данных"""
    try:
        print("🛠️ Отладочный endpoint вызван")

        # Проверяем доступ к данным
        total_places = Place.query.count()
        total_reviews = Review.query.count()
        total_users = User.query.count()

        # Проверяем последние отзывы
        recent_reviews = Review.query.order_by(Review.created_at.desc()).limit(3).all()
        reviews_data = []
        for review in recent_reviews:
            reviews_data.append({
                'id': review.id,
                'username': review.username,
                'rating': review.rating,
                'comment': review.comment
            })

        # Проверяем сессию
        session_info = {
            'username': session.get('username'),
            'has_session': 'username' in session
        }

        return jsonify({
            'status': 'ok',
            'database': {
                'total_places': total_places,
                'total_reviews': total_reviews,
                'total_users': total_users,
                'recent_reviews_count': len(recent_reviews)
            },
            'session': session_info,
            'recent_reviews': reviews_data
        })
    except Exception as e:
        print(f"❌ Ошибка в отладочном endpoint: {e}")
        return jsonify({'error': str(e)}), 500

# Декоратор для проверки авторизации администратора
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Требуется авторизация', 'error')
            return redirect(url_for('index'))

        user = User.query.filter_by(username=session['username']).first()

        # Добавляем current_user в контекст запроса
        from flask import g
        g.current_user = user

        return f(*args, **kwargs)

    return decorated_function

@app.route('/admin/api/stats')
@admin_required
def admin_stats():
    try:
        # Общая статистика
        total_places = Place.query.count()
        total_reviews = Review.query.count()
        total_users = User.query.count()

        # Средний рейтинг
        avg_rating_result = db.session.query(db.func.avg(Review.rating)).scalar()
        avg_rating = round(avg_rating_result, 2) if avg_rating_result else 0.0

        # Последние отзывы
        recent_reviews = Review.query.order_by(Review.created_at.desc()).limit(10).all()
        reviews_data = []
        for review in recent_reviews:
            # Пробуем найти место по ID
            place = None
            if review.restaurant_id.isdigit():
                place = Place.query.get(int(review.restaurant_id))
            else:
                # Если ID не цифровой, ищем по slug
                place = Place.query.filter_by(slug=review.restaurant_id).first()

            reviews_data.append({
                'id': review.id,
                'username': review.username,
                'rating': review.rating,
                'comment': review.comment,
                'created_at': review.created_at.isoformat(),
                'place_title': place.title if place else review.restaurant_id
            })

        return jsonify({
            'total_places': total_places,
            'total_reviews': total_reviews,
            'total_users': total_users,
            'avg_rating': avg_rating,
            'recent_reviews': reviews_data
        })

    except Exception as e:
        print(f"Error in admin_stats: {e}")
        return jsonify({'error': str(e)}), 500

# API для получения всех отзывов
@app.route('/admin/api/reviews')
@admin_required
def admin_reviews():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20

        reviews = Review.query.order_by(Review.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        reviews_data = []
        for review in reviews.items:
            # Пробуем найти место по ID
            place = None
            if review.restaurant_id.isdigit():
                place = Place.query.get(int(review.restaurant_id))
            else:
                place = Place.query.filter_by(slug=review.restaurant_id).first()

            reviews_data.append({
                'id': review.id,
                'username': review.username,
                'rating': review.rating,
                'comment': review.comment,
                'created_at': review.created_at.isoformat(),
                'likes': review.likes or 0,
                'dislikes': review.dislikes or 0,
                'place_title': place.title if place else review.restaurant_id,
                'restaurant_id': review.restaurant_id
            })

        return jsonify({
            'reviews': reviews_data,
            'total': reviews.total,
            'pages': reviews.pages,
            'current_page': page
        })

    except Exception as e:
        print(f"Error in admin_reviews: {e}")
        return jsonify({'error': str(e)}), 500

# API для удаления отзыва
@app.route('/admin/api/reviews/<int:review_id>', methods=['DELETE'])
@admin_required
def admin_delete_review(review_id):
    try:
        review = Review.query.get_or_404(review_id)
        restaurant_id = review.restaurant_id

        db.session.delete(review)
        db.session.commit()

        # Обновляем статистику ресторана
        update_restaurant_stats(restaurant_id)

        return jsonify({'success': True, 'message': 'Отзыв удален'})

    except Exception as e:
        db.session.rollback()
        print(f"Error deleting review: {e}")
        return jsonify({'error': str(e)}), 500

# API для редактирования отзыва
@app.route('/admin/api/reviews/<int:review_id>', methods=['PUT'])
@admin_required
def admin_edit_review(review_id):
    try:
        data = request.get_json()
        review = Review.query.get_or_404(review_id)

        if 'rating' in data:
            new_rating = int(data['rating'])
            if new_rating < 1 or new_rating > 5:
                return jsonify({'error': 'Рейтинг должен быть от 1 до 5'}), 400
            review.rating = new_rating

        if 'comment' in data:
            review.comment = data['comment']

        review.updated_at = datetime.utcnow()
        db.session.commit()

        # Обновляем статистику ресторана
        update_restaurant_stats(review.restaurant_id)

        return jsonify({'success': True, 'message': 'Отзыв обновлен'})

    except Exception as e:
        db.session.rollback()
        print(f"Error editing review: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/api/users', methods=['GET'])
@admin_required
def get_admin_users():
    """Получение списка всех администраторов"""
    try:
        users = User.query.all()
        current_user = User.query.filter_by(username=session['username']).first()

        users_data = []
        for user in users:
            users_data.append({
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'role_display': get_role_display(user.role),
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'can_edit': can_edit_user(current_user, user),
                'can_delete': can_delete_user(current_user, user)
            })

        return jsonify({'users': users_data})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_role_display(role):
    """Отображаемое название роли"""
    role_names = {
        'trainee': 'Стажёр',
        'moderator': 'Модератор',
        'editor': 'Редактор',
        'admin': 'Администратор'
    }
    return role_names.get(role, role)

def can_edit_user(current_user, target_user):
    """Может ли текущий пользователь редактировать целевого"""
    if current_user.role == 'admin':
        return target_user.username != 'admin'  # Нельзя редактировать главного админа
    elif current_user.role == 'editor':
        return target_user.role in ['trainee', 'moderator']
    elif current_user.role == 'moderator':
        return target_user.role == 'trainee'
    return False

def can_delete_user(current_user, target_user):
    """Может ли текущий пользователь удалить целевого"""
    return can_edit_user(current_user, target_user)  # Те же правила

@app.route('/admin/api/users/<int:user_id>/role', methods=['PUT'])
@admin_required
def admin_change_user_role(user_id):
    """API для изменения роли пользователя"""
    try:
        current_user = User.query.filter_by(username=session['username']).first()
        target_user = User.query.get_or_404(user_id)

        data = request.get_json()
        new_role = data.get('role')

        if not new_role or new_role not in ['trainee', 'moderator', 'editor', 'admin']:
            return jsonify({'error': 'Некорректная роль'}), 400

        # Проверка прав
        if not current_user.can_manage_user(target_user):
            return render_template('Error.html', error_code=403, error_message="Недостаточно прав для изменения этого пользователя"), 403

        # Нельзя изменять главного админа
        if target_user.username == 'admin' and current_user.username != 'admin':
            return render_template('Error.html', error_code=403, error_message="Нельзя изменять главного администратора"), 403


        # Нельзя понижать себя
        if target_user.id == current_user.id and new_role != current_user.role:
            return jsonify({'error': 'Нельзя изменять свою собственную роль'}), 403

        target_user.role = new_role
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Роль пользователя {target_user.username} изменена на {get_role_display_name(new_role)}'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    """API для удаления пользователя"""
    try:
        current_user = User.query.filter_by(username=session['username']).first()
        target_user = User.query.get_or_404(user_id)

        # Проверка прав
        if not current_user.can_manage_user(target_user):
            return jsonify({'error': 'Недостаточно прав для удаления этого пользователя'}), 403

        # Нельзя удалить главного админа
        if target_user.username == 'admin':
            return jsonify({'error': 'Нельзя удалить главного администратора'}), 403

        # Нельзя удалить себя
        if target_user.id == current_user.id:
            return jsonify({'error': 'Нельзя удалить себя'}), 403

        db.session.delete(target_user)
        db.session.commit()

        return jsonify({'success': True, 'message': 'Пользователь удален'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/admin/api/users', methods=['POST'])
@admin_required
@permission_required('manage_trainees')
def admin_create_user():
    """API для создания нового пользователя"""
    try:
        current_user = User.query.filter_by(username=session['username']).first()
        data = request.get_json()

        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'trainee')
        full_name = data.get('full_name')
        email = data.get('email')

        if not username or not password:
            return jsonify({'error': 'Логин и пароль обязательны'}), 400

        # Проверяем, что текущий пользователь может создавать пользователей с такой ролью
        role_hierarchy = {'trainee': 1, 'moderator': 2, 'editor': 3, 'admin': 4}
        if role_hierarchy.get(role, 0) > role_hierarchy.get(current_user.role, 0):
            return jsonify({'error': 'Недостаточно прав для создания пользователя с такой ролью'}), 403

        # Проверяем, не существует ли уже пользователь с таким логином
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'error': 'Пользователь с таким логином уже существует'}), 400

        # Создаем пользователя
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            username=username,
            password=hashed_password,
            role=role,
            full_name=full_name,
            email=email,
            is_active=True
        )

        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Пользователь {username} создан как {get_role_display_name(role)}',
            'user': {
                'id': new_user.id,
                'username': new_user.username,
                'role': new_user.role,
                'role_display': get_role_display_name(new_user.role),
                'full_name': new_user.full_name,
                'email': new_user.email
            }
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/api/change_role', methods=['POST'])
@admin_required
def change_user_role():
    """API для изменения роли пользователя"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        new_role = data.get('role')

        if not user_id or not new_role:
            return jsonify({'error': 'Missing user_id or role'}), 400

        if new_role not in ['trainee', 'moderator', 'editor']:
            return jsonify({'error': 'Invalid role'}), 400

        user = User.query.get_or_404(user_id)

        # Проверки безопасности
        if user.username == 'admin':
            return jsonify({'error': 'Cannot change admin role'}), 403

        user.role = new_role
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Роль пользователя {user.username} изменена на {new_role}'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

#Админские штуки - КОНЕЦ



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

def register_user(username, password, secret_key, role='trainee'):
    try:
        if secret_key != app.config['SECRET_KEY']:
            return False, "Неверный секретный ключ."

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return False, "Пользователь с таким логином уже существует."

        # Хеширование пароля
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(
            username=username,
            password=hashed_password,
            role=role
        )
        db.session.add(new_user)
        db.session.commit()
        return True, f"Пользователь {username} успешно зарегистрирован как {role}."

    except Exception as e:
        return False, str(e)

# Добавьте эту функцию для проверки лимита отзывов
def check_review_limit_per_restaurant(user_token, restaurant_id):
    """Проверяет лимит отзывов (1 отзыв в день на ресторан)"""
    try:
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
    print(f"🔍 Запрошены отзывы для restaurant_id: {restaurant_id}")

    if not restaurant_id:
        return jsonify({'error': 'restaurant_id is required'}), 400

    try:
        reviews = Review.query.filter_by(restaurant_id=restaurant_id) \
            .order_by(Review.created_at.desc()) \
            .all()

        print(f"📊 Найдено {len(reviews)} отзывов для {restaurant_id}")

        reviews_data = []
        for review in reviews:
            reviews_data.append({
                'id': review.id,
                'restaurant_id': review.restaurant_id,  # Добавляем для отладки
                'username': review.username,
                'rating': review.rating,
                'comment': review.comment,
                'created_at': review.created_at.isoformat(),
                'likes': review.likes or 0,
                'dislikes': review.dislikes or 0,
                'user_token': review.user_token,
                'device_fingerprint': review.device_fingerprint,
                'user_ratings': review.user_ratings or {}
            })

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
    if request.method == 'POST':
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

            # Проверяем лимит
            if not check_review_limit_per_restaurant(user_token, restaurant_id):
                return jsonify({'error': 'Вы уже оставляли отзыв для этого заведения сегодня'}), 429

            # Создаем отзыв
            review = Review(
                restaurant_id=restaurant_id,
                username=data['username'],
                rating=rating,
                comment=data.get('comment', ''),
                user_token=user_token,
                device_fingerprint=device_fingerprint,
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
            db.session.refresh(review)

            # Обновляем статистику ресторана
            update_restaurant_stats(restaurant_id)

            # ВАЖНО: Возвращаем JSON, а не HTML
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

            print("✅ Отправляем JSON ответ клиенту:", response_data)
            return jsonify(response_data), 201  # ✅ ВАЖНО: возвращаем JSON

        except Exception as e:
            print(f"❌ Ошибка при создании отзыва: {str(e)}")
            import traceback
            traceback.print_exc()
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

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
        return render_template('Error.html', error_code=500, error_message=e), 500

@app.route('/api/migrate_legacy_reviews', methods=['POST'])
def migrate_legacy_reviews():
    """Миграция legacy отзывов ТОЛЬКО для текущего пользователя"""
    try:
        data = request.get_json()
        user_token = data.get('user_token')
        device_fingerprint = data.get('device_fingerprint')

        if not user_token or not device_fingerprint:
            return render_template('Error.html', error_code=400, error_message="пользовательской токен и устройство не совподают"), 400

        # Находим legacy отзывы для текущего пользователя
        user_ip = request.remote_addr

        # Ищем legacy отзывы
        legacy_reviews = Review.query.filter(
            (Review.user_token.startswith('legacy_token_'))

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
        return render_template('Error.html', error_code=500, error_message=e), 500

@app.route('/api/debug/reviews')
def debug_review(review_id):
    """Отладочная информация по отзыву"""
    try:
        review = Review.query.get(review_id)
        if not review:
            return render_template('Error.html', error_code=404), 404

        return jsonify({
            'id': review.id,
            'username': review.username,
            'user_token': review.user_token,
            'device_fingerprint': review.device_fingerprint,
            'created_at': review.created_at.isoformat(),
            'ip_address': review.ip_address
        })
    except Exception as e:
        return render_template('Error.html', error_code=500, error_message=e), 500

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
        return render_template('Error.html', error_code=500, error_message=e), 500

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
        return render_template('Error.html', error_code=500, error_message=e), 500

@app.route('/api/reviews/<int:review_id>', methods=['DELETE'])
def delete_review(review_id):
    try:
        data = request.get_json()
        print(f"=== УДАЛЕНИЕ ОТЗЫВА {review_id} ===")
        print(f"Данные: {data}")

        if not data:
            return render_template('Error.html', error_code=400, error_message="Не предоставлено данных"), 400

        user_token = data.get('user_token')
        device_fingerprint = data.get('device_fingerprint')

        if not user_token or not device_fingerprint:
            return render_template('Error.html', error_code=400, error_message="Пользовательский токен и устройство не то"), 400

        # Находим отзыв
        review = Review.query.get(review_id)
        if not review:
            return render_template('Error.html', error_code=404), 404

        print(f"User token в отзыве: {review.user_token}")
        print(f"User token из запроса: {user_token}")

        # Проверяем права на удаление
        if not review.user_token or review.user_token != user_token:
            print("Ошибка: несовпадение user_token")
            return render_template('Error.html', error_code=403, error_message="Пользовательский токен не совподает"), 403

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
            return render_template('Error.html', error_code=403, error_message="Время истекло"), 403


        # Сохраняем restaurant_id для обновления статистики
        restaurant_id = review.restaurant_id

        # Удаляем отзыв
        db.session.delete(review)
        db.session.commit()

        # ОБНОВЛЯЕМ СТАТИСТИКУ ПОСЛЕ УДАЛЕНИЯ
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
        return render_template('Error.html', error_code=500), 500

def fix_image_paths():
    """Исправление путей изображений на английские"""
    with app.app_context():
        # Обновляем все пути в базе
        places = Place.query.all()
        for place in places:
            if place.image_path and 'Фотки зданий' in place.image_path:
                place.image_path = place.image_path.replace('Фотки зданий', 'images')

        db.session.commit()
        print("✅ Пути изображений обновлены")


def initialize_icons():
    """Добавление иконок категорий в базу с английскими путями"""
    with app.app_context():
        category_icons = {
            'Ресторан': 'icon_restaurant.png',
            'Кафе': 'icon_cafe.png',
            'Магазин': 'icon_shop.png',
            'Музей': 'icon_museum.png',
            'Театр': 'icon_theatre.png',
            'Библиотека': 'icon_library.png',
            'Парк': 'icon_park.png',
            'Кинотеатр': 'icon_cinema.png',
            'Спортплощадка': 'icon_sports.png',
            'Церковь': 'icon_church.png',
            'Гостиница': 'icon_hotel.png'
        }

        for category, icon in category_icons.items():
            existing_icon = Place.query.filter_by(category='Иконка', title=category).first()

            if not existing_icon:
                icon_place = Place(
                    title=category,
                    category='Иконка',
                    category_en='icon',
                    image_path=f'images/{icon}',  # Английский путь
                    slug=f'icon_{category.lower()}'
                )
                db.session.add(icon_place)

        db.session.commit()
        print("✅ Иконки категорий добавлены в базу")

def create_category_icon(category_name):
    """Создает запись иконки для новой категории"""
    # Проверяем, есть ли уже иконка
    existing_icon = Place.query.filter_by(category='Иконка', title=category_name).first()

    if not existing_icon:
        # Создаем новую запись иконки
        new_icon = Place(
            title=category_name,
            category='Иконка',
            category_en='icon',
            image_path='Фотки зданий/ИконкаМеста.png',  # БЕЗ static/!
            slug=f'icon_{category_name.lower().replace(" ", "_")}'
        )
        db.session.add(new_icon)
        db.session.commit()
        print(f"✅ Создана запись иконки для категории: {category_name}")

@app.route('/add_place', methods=['GET', 'POST'])
@admin_required
def add_place():
    """Добавление нового заведения"""
    user = User.query.filter_by(username=session['username']).first()

    # Разрешаем доступ стажёрам, модераторам, редакторам и админам
    if user.role not in ['trainee', 'moderator', 'editor', 'admin']:
        return render_template('Error.html', error_code=403, error_message="Доступ запрещён"), 403

    # Получаем существующие категории из базы
    categories = db.session.query(Place.category).distinct().all()
    categories = [cat[0] for cat in categories if cat[0]]  # Извлекаем из кортежей

    # Стандартные категории если нет в базе
    standard_categories = ['Ресторан', 'Кафе', 'Магазин', 'Музей', 'Театр', 'Библиотека',
                           'Парк', 'Кинотеатр', 'Спортплощадка', 'Церковь', 'Гостиница', 'Иконка']

    # Объединяем и убираем дубликаты
    all_categories = list(set(categories + standard_categories))
    all_categories.sort()

    # Получаем существующие заведения для проверки дубликатов
    existing_places = Place.query.with_entities(Place.slug).all()
    existing_places = [place[0] for place in existing_places if place[0]]

    if request.method == 'POST':
        try:
            # Получаем данные из формы
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            telephone = request.form.get('telephone', '').strip()
            address = request.form.get('address', '').strip()
            existing_category = request.form.get('existing_category', '').strip()
            new_category = request.form.get('new_category', '').strip()
            slug = request.form.get('slug', '').strip()
            tags = request.form.get('tags', '').strip()
            latitude = request.form.get('latitude', '').strip()
            longitude = request.form.get('longitude', '').strip()
            working_hours = request.form.get('working_hours', '{}')
            menu = request.form.get('menu', '{}')

            # Если создана новая категория
            if new_category and not existing_category:
                # Обрабатываем новую категорию
                handle_new_category(new_category)

            # Определяем финальную категорию
            category = existing_category or new_category
            if not category:
                flash('Категория обязательна для заполнения', 'error')
                return render_template('admin_add_place.html',
                                       categories=all_categories,
                                       existing_places=existing_places,
                                       current_user=user)

            # Определяем category_en
            category_mapping = {
                'Ресторан': 'restaurant', 'Кафе': 'cafe', 'Магазин': 'shop',
                'Музей': 'museum', 'Театр': 'theatre', 'Библиотека': 'library',
                'Парк': 'park', 'Кинотеатр': 'cinema', 'Спортплощадка': 'sports',
                'Церковь': 'church', 'Гостиница': 'hotel', 'Иконка': 'icon'
            }
            category_en = category_mapping.get(category, category.lower().replace(' ', '_'))

            # Генерируем slug если не указан
            if not slug and title:
                slug = generate_slug(title)

            # Обработка файла
            image_path = None
            if 'image' in request.files:
                file = request.files['image']
                if file.filename != '':
                    if not allowed_file(file.filename):
                        flash('Недопустимый тип файла', 'error')
                        return render_template('admin_add_place.html',
                                               categories=all_categories,
                                               existing_places=existing_places,
                                               current_user=user)

                    filename = secure_filename(file.filename)
                    if not filename:
                        flash('Недопустимое имя файла', 'error')
                        return render_template('admin_add_place.html',
                                               categories=all_categories,
                                               existing_places=existing_places,
                                               current_user=user)

                    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    try:
                        file.save(save_path)
                        image_path = 'Фотки зданий/' + filename
                    except Exception as e:
                        app.logger.error(f'Ошибка сохранения файла: {str(e)}')
                        flash('Ошибка при сохранении файла', 'error')
                        return render_template('admin_add_place.html',
                                               categories=all_categories,
                                               existing_places=existing_places,
                                               current_user=user)

            # Создаем новую запись
            new_place = Place(
                title=title or None,
                description=description or None,
                telephone=telephone or None,
                address=address or None,
                image_path=image_path,
                category=category,
                category_en=category_en,
                latitude=float(latitude) if latitude else None,
                longitude=float(longitude) if longitude else None,
                working_hours=working_hours,
                menu=menu,
                tags=tags or None,
                slug=slug
            )

            db.session.add(new_place)
            db.session.commit()

            flash('Место успешно добавлено!', 'success')
            return redirect(url_for('admin_places'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Ошибка при добавлении места: {str(e)}')
            flash(f'Ошибка при добавлении места: {str(e)}', 'error')
            return render_template('admin_add_place.html',
                                   categories=all_categories,
                                   existing_places=existing_places,
                                   current_user=user)

    # GET запрос
    return render_template('admin_add_place.html',
                           categories=all_categories,
                           existing_places=existing_places,
                           current_user=user)

def generate_slug(title):
    """Генерация slug из русского названия"""
    # Транслитерация кириллицы в латиницу
    translit_dict = {
        'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd', 'е': 'e', 'ё': 'yo',
        'ж': 'zh', 'з': 'z', 'и': 'i', 'й': 'y', 'к': 'k', 'л': 'l', 'м': 'm',
        'н': 'n', 'о': 'o', 'п': 'p', 'р': 'r', 'с': 's', 'т': 't', 'у': 'u',
        'ф': 'f', 'х': 'h', 'ц': 'ts', 'ч': 'ch', 'ш': 'sh', 'щ': 'sch', 'ъ': '',
        'ы': 'y', 'ь': '', 'э': 'e', 'ю': 'yu', 'я': 'ya'
    }

    # Приводим к нижнему регистру и транслитерируем
    slug = ''.join(translit_dict.get(c, c) for c in title if c.isalnum() or c.isspace())

    # Заменяем пробелы на дефисы и удаляем лишние символы
    slug = re.sub(r'[^\w\s-]', '', slug)
    slug = re.sub(r'[-\s]+', '-', slug).strip('-')
    slug = ''.join(translit_dict.get(c, c) for c in title)
    slug = re.sub(r'[^a-z0-9-]', '-', slug)  # Заменяем не-буквы на дефисы
    slug = re.sub(r'-+', '-', slug).strip('-')  # Убираем лишние дефисы
    return slug

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

@app.route("/")
def index():
    # Получаем все уникальные категории из базы данных (кроме Иконок)
    categories_from_db = db.session.query(Place.category).filter(Place.category != 'Иконка').distinct().all()
    categories_from_db = [cat[0] for cat in categories_from_db if cat[0]]

    # Стандартные категории для гарантии
    standard_categories = ['Ресторан', 'Кафе', 'Магазин', 'Музей', 'Театр', 'Библиотека',
                           'Парк', 'Кинотеатр', 'Спортплощадка', 'Церковь', 'Гостиница']

    # Объединяем категории
    all_categories = list(set(categories_from_db + standard_categories))
    all_categories.sort()

    # Получаем иконки для категорий из базы
    category_data = {}
    for category in all_categories:
        icon_place = Place.query.filter_by(category='Иконка', title=category).first()

        if icon_place and icon_place.image_path:
            # Прямой путь без url_for (экспериментально)
            icon_url = f'/static/{icon_place.image_path}'
        else:
            icon_url = '/static/Фотки зданий/ИконкаМеста.png'

        # Генерируем URL для категории
        if category in ['Ресторан', 'Кафе', 'Магазин', 'Музей', 'Театр', 'Библиотека',
                        'Парк', 'Кинотеатр', 'Спортплощадка', 'Церковь', 'Гостиница']:
            category_url = f'/{category.lower()}'
        else:
            category_en = category.lower().replace(' ', '_')
            category_url = f'/{category_en}'

        category_data[category] = {
            'url': category_url,
            'icon': icon_url
        }

    return render_template("index.html",
                           title="Городской гид",
                           categories=all_categories,
                           category_data=category_data)

def handle_new_category(category_name):
    """Обработка новой категории - просто логируем"""
    import os

    icon_path = os.path.join(app.static_folder, 'Фотки зданий', f'Иконка{category_name}.png')
    default_icon = os.path.join(app.static_folder, 'Фотки зданий', 'ИконкаМеста.png')

    # Если иконка не существует, используем иконку по умолчанию
    if not os.path.exists(icon_path):
        print(f"⚠️  Для категории '{category_name}' не найдена иконка. Используется иконка по умолчанию.")
        # Можно добавить логику копирования иконки по умолчанию если нужно
        # import shutil
        # if os.path.exists(default_icon):
        #     shutil.copy2(default_icon, icon_path)

    return True

@app.route("/test", methods=['GET', 'POST'])
def test():
    return render_template("ЛичныеСтраницы/test.html", title="Городской гид")

@app.route("/search", methods=["GET", "POST"])
def search():
    """Улучшенный поиск по базе данных с поддержкой тегов и улицы"""
    try:
        # Получаем запрос из GET или POST параметров
        if request.method == 'POST':
            query = request.form.get('query', '').strip()
        else:
            query = request.args.get('q', '').strip()

        page = request.args.get('page', 1, type=int)
        per_page = 10

        print(f"Поисковый запрос: '{query}', страница: {page}")

        if not query:
            return render_template("results.html",
                                   results=[],
                                   query="",
                                   title="Поиск",
                                   current_page=1,
                                   total_pages=0,
                                   total_results=0)

        # Базовый запрос с улучшенным поиском
        base_query = advanced_search(query)

        # Получаем общее количество результатов
        total_results = base_query.count()
        total_pages = math.ceil(total_results / per_page) if total_results > 0 else 1

        print(f"Найдено результатов: {total_results}, страниц: {total_pages}")

        # Получаем результаты для текущей страницы
        results = base_query.offset((page - 1) * per_page).limit(per_page).all()

        # Формируем данные для шаблона
        results_data = []
        for place in results:
            try:
                # ПРАВИЛЬНО получаем рейтинг - несколько способов
                avg_rating = 0.0
                review_count = 0

                # Способ 1: Ищем в таблице Restaurant по ID места
                restaurant = Restaurant.query.get(str(place.id))
                if restaurant and restaurant.total_rating is not None:
                    avg_rating = round(float(restaurant.total_rating), 1)
                    review_count = restaurant.review_count or 0
                    print(f"Рейтинг из Restaurant для {place.title}: {avg_rating}")
                else:
                    # Способ 2: Ищем по slug
                    if place.slug:
                        restaurant_by_slug = Restaurant.query.get(place.slug)
                        if restaurant_by_slug and restaurant_by_slug.total_rating is not None:
                            avg_rating = round(float(restaurant_by_slug.total_rating), 1)
                            review_count = restaurant_by_slug.review_count or 0
                            print(f"Рейтинг из Restaurant по slug для {place.title}: {avg_rating}")
                    else:
                        # Способ 3: Вычисляем из отзывов
                        reviews = Review.query.filter_by(restaurant_id=str(place.id)).all()
                        if reviews:
                            total_rating = sum(review.rating for review in reviews)
                            avg_rating = round(total_rating / len(reviews), 1)
                            review_count = len(reviews)
                            print(f"Рейтинг из Review для {place.title}: {avg_rating}")

                # Формируем URL
                if place.slug and place.category_en:
                    place_url = url_for('place_page_by_slug',
                                        category_en=place.category_en,
                                        slug=place.slug,
                                        _external=False)
                else:
                    place_url = url_for('restaurant_page', id=place.id, _external=False)

                # Обрезаем длинное описание
                description = place.description or ''
                if len(description) > 200:
                    description = description[:200] + '...'

                results_data.append({
                    'id': place.id,
                    'title': place.title or 'Без названия',
                    'description': description,
                    'telephone': place.telephone or '',
                    'address': place.address or '',
                    'image_path': place.image_path,
                    'category': place.category or 'Не указана',
                    'slug': place.slug,
                    'category_en': place.category_en,
                    'avg_rating': avg_rating,
                    'review_count': review_count,
                    'url': place_url,
                    'latitude': place.latitude,
                    'longitude': place.longitude
                })
            except Exception as e:
                print(f"Ошибка обработки места {place.id}: {e}")
                continue

        print(f"Успешно обработано результатов: {len(results_data)}")

        # Обычный запрос - рендерим HTML
        return render_template("results.html",
                               results=results_data,
                               query=query,
                               title=f"Поиск: {query}",
                               current_page=page,
                               total_pages=total_pages,
                               total_results=total_results)

    except Exception as e:
        print(f"Критическая ошибка поиска: {e}")
        import traceback
        traceback.print_exc()

        return render_template("results.html",
                               results=[],
                               query=query if 'query' in locals() else '',
                               title="Поиск",
                               error="Произошла ошибка при поиске")

@app.route('/api/search')
def api_search():
    """API для AJAX поиска с пагинацией, фильтрами и расстояниями"""
    try:
        query = request.args.get('q', '').strip()
        page = request.args.get('page', 1, type=int)
        sort_by = request.args.get('sort_by', 'default')
        user_lat = request.args.get('lat', type=float)
        user_lon = request.args.get('lon', type=float)
        per_page = 10

        if not query:
            return jsonify({
                'results': [],
                'total_results': 0,
                'total_pages': 0,
                'current_page': page,
                'query': query
            })

        # Базовый запрос - исключаем иконки
        base_query = Place.query.filter(Place.category != 'Иконка')
        base_query = advanced_search(query)

        # Получаем общее количество
        total_results = base_query.count()
        total_pages = math.ceil(total_results / per_page) if total_results > 0 else 1

        # Получаем результаты для страницы
        results = base_query.offset((page - 1) * per_page).limit(per_page).all()

        # Формируем данные с расчетом расстояний если есть координаты пользователя
        results_data = []
        for place in results:
            restaurant = Restaurant.query.get(str(place.id))
            avg_rating = round(float(restaurant.total_rating), 1) if restaurant and restaurant.total_rating else 0.0
            review_count = restaurant.review_count if restaurant else 0

            if place.slug and place.category_en:
                place_url = url_for('place_page_by_slug', category_en=place.category_en, slug=place.slug,
                                    _external=False)
            else:
                place_url = url_for('restaurant_page', id=place.id, _external=False)

            # Рассчитываем расстояние если есть координаты пользователя и места
            distance = None
            if user_lat and user_lon and place.latitude and place.longitude:
                distance = calculate_distance(user_lat, user_lon, place.latitude, place.longitude)

            place_data = {
                'id': place.id,
                'title': place.title or 'Без названия',
                'description': place.description or '',
                'telephone': place.telephone or '',
                'address': place.address or '',
                'image_path': place.image_path,
                'avg_rating': avg_rating,
                'review_count': review_count,
                'url': place_url,
                'latitude': place.latitude,
                'longitude': place.longitude,
                'distance': distance
            }
            results_data.append(place_data)

        # Применяем сортировку на стороне сервера для расстояний
        if sort_by == 'distance' and user_lat and user_lon:
            results_data.sort(key=lambda x: x['distance'] if x['distance'] else float('inf'))
        elif sort_by == 'rating_high':
            results_data.sort(key=lambda x: x['avg_rating'], reverse=True)
        elif sort_by == 'rating_low':
            results_data.sort(key=lambda x: x['avg_rating'])
        elif sort_by == 'name_asc':
            results_data.sort(key=lambda x: (x['title'] or '').lower())
        elif sort_by == 'name_desc':
            results_data.sort(key=lambda x: (x['title'] or '').lower(), reverse=True)

        return jsonify({
            'results': results_data,
            'total_results': total_results,
            'total_pages': total_pages,
            'current_page': page,
            'query': query
        })

    except Exception as e:
        print(f"Ошибка в API поиска: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def calculate_distance(lat1, lon1, lat2, lon2):
    """Расчет расстояния между двумя точками в км"""
    from math import radians, sin, cos, sqrt, atan2

    R = 6371  # Радиус Земли в км

    lat1_rad = radians(lat1)
    lon1_rad = radians(lon1)
    lat2_rad = radians(lat2)
    lon2_rad = radians(lon2)

    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad

    a = sin(dlat / 2) ** 2 + cos(lat1_rad) * cos(lat2_rad) * sin(dlon / 2) ** 2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    return R * c

@app.route('/restaurant/<int:id>')
def restaurant_page(id):
    """Универсальный маршрут для всех ресторанов по ID"""
    try:
        place = Place.query.get_or_404(id)
        print(f"Загружаем место: {place.title}, ID: {id}")

        # Пробуем найти индивидуальный шаблон, если нет - используем общий
        template_name = f'ЛичныеСтраницы/{place.title}.html'

        # Проверяем существует ли индивидуальный шаблон
        import os
        template_path = os.path.join(app.root_path, 'templates', template_name)

        if os.path.exists(template_path):
            return render_template(template_name, place=place)
        else:
            # Используем общий шаблон
            return render_template('place_template.html', place=place)

    except Exception as e:
        print(f"Ошибка загрузки страницы {id}: {e}")
        abort(404)  # ✅ Правильное использование 404

@app.route('/<category_en>/<slug>')
def place_page_by_slug(category_en, slug):
    """Универсальный маршрут для всех мест по slug"""
    print(f"Поиск места: category_en={category_en}, slug={slug}")

    place = Place.query.filter_by(category_en=category_en, slug=slug).first_or_404()
    print(f"Найдено место: {place.title}")

    # Пробуем найти индивидуальный шаблон
    template_name = f'ЛичныеСтраницы/{place.title}.html'
    import os
    template_path = os.path.join(app.root_path, 'templates', template_name)

    if os.path.exists(template_path):
        return render_template(template_name, place=place)
    else:
        return render_template('place_template.html', place=place)

# ПОТОМ маршрут с ОДНИМ параметром
@app.route('/<category_type>')
def universal_category_page(category_type):
    """Универсальный маршрут для ВСЕХ категорий"""

    # Сначала проверяем, является ли это специальным маршрутом
    SPECIAL_ROUTES = ['404', '500', 'test', 'admin', 'debug', 'favorites', 'add_place']
    if category_type in SPECIAL_ROUTES:
        return render_template('error.html',
                               error_code=404,
                               error_name="Страница не найдена"), 404

    # Получаем все категории из базы
    all_categories = db.session.query(Place.category, Place.category_en).distinct().all()

    # Создаем словарь соответствия category_en -> category
    category_mapping = {}
    for cat_ru, cat_en in all_categories:
        if cat_ru and cat_en:
            category_mapping[cat_en] = cat_ru

    # Проверяем, существует ли запрошенная категория
    if category_type not in category_mapping:
        return render_template('Error.html',
                               error_code=404,
                               error_name="Категория не найдена"), 404

    category_ru = category_mapping[category_type]

    page = request.args.get('page', 1, type=int)
    per_page = 10

    places_query = Place.query.filter_by(category=category_ru)
    total_places = places_query.count()
    total_pages = math.ceil(total_places / per_page) if total_places > 0 else 1

    places = places_query.offset((page - 1) * per_page).limit(per_page).all()

    # Получаем рейтинги из таблицы restaurants
    places_with_ratings = []
    for place in places:
        restaurant = None

        if place.slug:
            restaurant = Restaurant.query.get(place.slug)

        if not restaurant and place.category_en:
            restaurant = Restaurant.query.get(place.category_en)

        # Специальные случаи для обратной совместимости
        if not restaurant:
            special_cases = {
                'Brewmen': 'Brewmen',
            }
            if place.title in special_cases:
                restaurant = Restaurant.query.get(special_cases[place.title])

        if restaurant and restaurant.total_rating is not None:
            avg_rating = round(restaurant.total_rating, 1)
            review_count = restaurant.review_count or 0
        else:
            avg_rating = 0.0
            review_count = 0

        places_with_ratings.append({
            'place': place,
            'avg_rating': avg_rating,
            'review_count': review_count,
            'restaurant_found': bool(restaurant)
        })

    return render_template('category_template.html',
                           places=places,
                           places_with_ratings=places_with_ratings,
                           category_name=category_ru,
                           current_page=page,
                           total_pages=total_pages,
                           category_type=category_type)

@app.route('/update-restaurant-ratings')
def update_restaurant_ratings():
    """Принудительное обновление рейтингов для всех ресторанов"""
    try:
        places = Place.query.all()
        updated_count = 0

        for place in places:
            # Обновляем статистику для этого места
            update_restaurant_stats(str(place.id))
            updated_count += 1

        return jsonify({
            'success': True,
            'message': f'Обновлены рейтинги для {updated_count} мест',
            'updated_count': updated_count
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/filtered-places')
def api_filtered_places():
    """API для фильтрованного списка мест"""
    try:
        category = request.args.get('category')
        sort_by = request.args.get('sort_by', 'default')

        if not category:
            return jsonify({'error': 'Category is required'}), 400

        # Базовый запрос
        query = Place.query.filter_by(category=category)
        places = query.all()

        # Добавляем рейтинги
        places_with_ratings = []
        for place in places:
            avg_rating = get_average_rating(place.id)
            places_with_ratings.append({
                'id': place.id,
                'title': place.title,
                'description': place.description,
                'telephone': place.telephone,
                'address': place.address,
                'image_path': place.image_path,
                'category_en': place.category_en,
                'slug': place.slug,
                'avg_rating': avg_rating
            })

        # Сортировка
        if sort_by == 'rating_high':
            places_with_ratings.sort(key=lambda x: x['avg_rating'], reverse=True)
        elif sort_by == 'rating_low':
            places_with_ratings.sort(key=lambda x: x['avg_rating'])
        elif sort_by == 'name_asc':
            places_with_ratings.sort(key=lambda x: (x['title'] or '').lower())
        elif sort_by == 'name_desc':
            places_with_ratings.sort(key=lambda x: (x['title'] or '').lower(), reverse=True)

        return jsonify({
            'places': places_with_ratings,
            'total': len(places_with_ratings)
        })

    except Exception as e:
        print(f"Error in api_filtered_places: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def get_average_rating(place_id):
    """Получение средней оценки заведения из таблицы restaurants"""
    try:
        # Пробуем найти ресторан по ID
        restaurant = Restaurant.query.get(str(place_id))
        if restaurant and restaurant.total_rating:
            return round(restaurant.total_rating, 1)

        # Если нет в таблице restaurants, вычисляем из отзывов
        reviews = Review.query.filter_by(restaurant_id=str(place_id)).all()
        if not reviews:
            return 0

        total_rating = sum(review.rating for review in reviews)
        average_rating = total_rating / len(reviews)
        return round(average_rating, 1)

    except Exception as e:
        print(f"Error calculating average rating for place {place_id}: {e}")
        return 0

# API endpoint для AJAX загрузки
@app.route('/api/categories/<category_slug>')
def api_category_places(category_slug):
    """API для получения мест по категории"""
    CATEGORY_MAPPING = {
        'restaurant': 'Ресторан',
        'coffee': 'Кафе',
        'shop': 'Магазин',
        'museums': 'Музей',
        'theatre': 'Театр',
        'library': 'Библиотека',
        'park': 'Парк',
        'cinema': 'Кинотеатр',
        'sports': 'Спортплощадка',
        'church': 'Церковь',
        'hotels': 'Гостиница'
    }

    if category_slug not in CATEGORY_MAPPING:
        return jsonify({'error': 'Category not found'}), 404

    category_ru = CATEGORY_MAPPING[category_slug]
    page = request.args.get('page', 1, type=int)
    per_page = 10

    places_query = Place.query.filter_by(category=category_ru)
    total_places = places_query.count()
    total_pages = math.ceil(total_places / per_page)

    places = places_query.offset((page - 1) * per_page).limit(per_page).all()

    places_data = []
    for place in places:
        # Тот же алгоритм поиска что и в основной функции
        restaurant = None

        if place.slug:
            restaurant = Restaurant.query.get(place.slug)

        if not restaurant and place.category_en:
            restaurant = Restaurant.query.get(place.category_en)

        # Специальные случаи
        if not restaurant:
            special_cases = {
                'Brewmen': 'Brewmen',
            }
            if place.title in special_cases:
                restaurant = Restaurant.query.get(special_cases[place.title])

        if restaurant and restaurant.total_rating is not None:
            avg_rating = round(restaurant.total_rating, 1)
        else:
            avg_rating = 0.0

        places_data.append({
            'id': place.id,
            'title': place.title,
            'description': place.description,
            'telephone': place.telephone,
            'address': place.address,
            'image_path': place.image_path,
            'category_en': place.category_en,
            'slug': place.slug,
            'avg_rating': avg_rating,
            'latitude': place.latitude,  # Добавляем координаты
            'longitude': place.longitude
        })

    return jsonify({
        'places': places_data,
        'current_page': page,
        'total_pages': total_pages,
        'has_next': page < total_pages,
        'has_prev': page > 1
    })

@app.route('/api/popular-places-by-category')
def api_popular_places_by_category():
    """API для получения самых популярных заведений из каждой категории"""
    try:
        print("🔍 Starting popular places by category search...")

        # Получаем все уникальные категории (кроме Иконок)
        categories = db.session.query(Place.category).filter(
            Place.category != 'Иконка',
            Place.category.isnot(None)
        ).distinct().all()

        categories = [cat[0] for cat in categories if cat[0]]
        print(f"📂 Found categories: {categories}")

        popular_places = []

        for category in categories:
            print(f"🔎 Processing category: {category}")

            # Находим все места в категории
            places_in_category = Place.query.filter_by(category=category).all()
            print(f"   Found {len(places_in_category)} places in category")

            if not places_in_category:
                continue

            # Находим самое популярное место в категории
            best_place = None
            best_score = -1
            best_restaurant = None

            for place in places_in_category:
                # Ищем ресторан в таблице Restaurant по разным идентификаторам
                restaurant = None

                # Пробуем найти по ID места
                if place.id:
                    restaurant = Restaurant.query.get(str(place.id))

                # Если не нашли, пробуем по slug
                if not restaurant and place.slug:
                    restaurant = Restaurant.query.get(place.slug)

                # Если не нашли, пробуем по названию
                if not restaurant and place.title:
                    restaurant = Restaurant.query.filter_by(name=place.title).first()

                if restaurant and restaurant.total_rating is not None and restaurant.review_count:
                    # Считаем "популярность" как рейтинг * количество отзывов
                    score = restaurant.total_rating * restaurant.review_count

                    if score > best_score:
                        best_score = score
                        best_place = place
                        best_restaurant = restaurant
                        print(f"   🏆 New best place: {place.title} with score {score}")

            # Если не нашли через Restaurant, берем первое место в категории
            if not best_place:
                best_place = places_in_category[0]
                print(f"   📝 Using first place: {best_place.title}")

            if best_place:
                # Формируем URL
                if best_place.slug and best_place.category_en:
                    place_url = url_for('place_page_by_slug',
                                        category_en=best_place.category_en,
                                        slug=best_place.slug,
                                        _external=False)
                else:
                    place_url = url_for('restaurant_page', id=best_place.id, _external=False)

                # Получаем рейтинг и количество отзывов
                avg_rating = 0.0
                review_count = 0

                if best_restaurant:
                    avg_rating = round(float(best_restaurant.total_rating), 1)
                    review_count = best_restaurant.review_count
                else:
                    # Пробуем вычислить из отзывов
                    reviews = Review.query.filter_by(restaurant_id=str(best_place.id)).all()
                    if reviews:
                        total_rating = sum(review.rating for review in reviews)
                        avg_rating = round(total_rating / len(reviews), 1)
                        review_count = len(reviews)

                popular_places.append({
                    'category': category,
                    'place': {
                        'id': best_place.id,
                        'title': best_place.title or 'Без названия',
                        'description': best_place.description or 'Описание отсутствует',
                        'telephone': best_place.telephone or 'Телефон не указан',
                        'address': best_place.address or 'Адрес не указан',
                        'image_path': best_place.image_path,
                        'avg_rating': avg_rating,
                        'review_count': review_count,
                        'url': place_url
                    }
                })
                print(f"   ✅ Added {best_place.title} to popular places")

        print(f"🎯 Total popular places found: {len(popular_places)}")

        return jsonify({
            'success': True,
            'popular_places': popular_places
        })

    except Exception as e:
        print(f"❌ Error in api_popular_places_by_category: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/random-place')
def api_random_place():
    """API для получения случайного заведения"""
    try:
        # Получаем все места у которых есть slug (значит есть личная страница)
        places = Place.query.filter(Place.slug.isnot(None)).all()

        if not places:
            return jsonify({'success': False, 'message': 'No places found'}), 404  # ✅ Добавляем статус 404

        # Выбираем случайное место
        import random
        random_place = random.choice(places)

        # Формируем URL
        place_url = url_for('place_page_by_slug',
                            category_en=random_place.category_en,
                            slug=random_place.slug)

        return jsonify({
            'success': True,
            'place_url': place_url,
            'place_title': random_place.title
        })

    except Exception as e:
        print(f"Error in api_random_place: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500


@app.route('/api/popular-place')
def api_popular_place():
    """API для получения самого популярного заведения"""
    try:
        # Получаем все рестораны с рейтингом и количеством отзывов
        restaurants = Restaurant.query.filter(
            Restaurant.total_rating > 0,
            Restaurant.review_count > 0
        ).all()

        if not restaurants:
            return jsonify({'success': False, 'message': 'No rated places found'}), 404

        # Сортируем по критериям:
        popular_restaurant = max(restaurants, key=lambda r: (
            r.total_rating,  # основное - средний рейтинг
            r.review_count,  # второе - количество оценок
            r.last_updated.timestamp() if r.last_updated else 0  # третье - дата обновления
        ))

        # Находим соответствующее место
        place = None

        # Сначала ищем по slug
        if popular_restaurant.id:
            place = Place.query.filter_by(slug=popular_restaurant.id).first()

        # Если не нашли, ищем по названию
        if not place:
            place = Place.query.filter_by(title=popular_restaurant.name).first()

        # Если все еще не нашли, берем первое место с таким же рейтингом
        if not place:
            place = Place.query.first()

        if not place:
            return jsonify({'success': False, 'message': 'Place not found'}), 404

        # Формируем URL
        place_url = url_for('place_page_by_slug',
                            category_en=place.category_en,
                            slug=place.slug, _external=False)

        return jsonify({
            'success': True,
            'place': {
                'id': place.id,
                'title': place.title,
                'description': place.description,
                'telephone': place.telephone,
                'address': place.address,
                'image_path': place.image_path,
                'avg_rating': round(popular_restaurant.total_rating, 1),
                'review_count': popular_restaurant.review_count,
                'category': place.category,
                'url': place_url,
                'last_updated': popular_restaurant.last_updated.isoformat() if popular_restaurant.last_updated else None
            }
        })

    except Exception as e:
        print(f"Error in api_popular_place: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

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
@app.route("/favorites", methods=["GET"])
def favorites():
    print(url_for("favorites"))
    return render_template("favorites.html", title="Избранное")

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Главная страница админ-панели"""
    user = User.query.filter_by(username=session['username']).first()

    # Статистика
    stats = {
        'total_places': Place.query.count(),
        'total_reviews': Review.query.count(),
        'total_users': User.query.count(),
        'avg_rating': db.session.query(db.func.avg(Review.rating)).scalar() or 0
    }

    # Последние отзывы (только для тех, у кого есть права)
    recent_reviews = []
    if user.has_permission('edit_review'):
        recent_reviews = Review.query.order_by(Review.created_at.desc()).limit(10).all()
        # Добавляем название места к каждому отзыву
        for review in recent_reviews:
            place = Place.query.get(int(review.restaurant_id)) if review.restaurant_id.isdigit() else None
            review.place_title = place.title if place else review.restaurant_id

    return render_template('admin_dashboard.html',
                           current_user=user,
                           stats=stats,
                           recent_reviews=recent_reviews)

@app.route('/admin/users')
@admin_required
@permission_required('manage_trainees')
def admin_users():
    """Страница управления пользователями"""
    user = User.query.filter_by(username=session['username']).first()
    users = User.query.all()

    return render_template('admin_users.html',
                           current_user=user,
                           users=users)

@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    """Выход из админ-панели"""
    session.pop('username', None)
    flash('Вы успешно вышли из системы', 'success')
    return redirect(url_for('index'))


@app.route('/admin/')
@app.route('/admin')
@admin_required
def admin_panel():
    """Главная админ-панель - перенаправляем на заведения"""
    user = User.query.filter_by(username=session['username']).first()

    # Для всех ролей перенаправляем на заведения
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/places')
@admin_required
def admin_places():
    """Страница управления заведениями с пагинацией"""
    user = User.query.filter_by(username=session['username']).first()

    # Разрешаем доступ стажёрам, модераторам, редакторам и админам
    if user.role not in ['trainee', 'moderator', 'editor', 'admin']:
        return render_template('Error.html', error_code=403, error_message="Доступ запрещён"), 403

    # Пагинация - 50 заведений на страницу
    page = request.args.get('page', 1, type=int)
    per_page = 50

    places_pagination = Place.query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    return render_template('admin_places.html',
                           current_user=user,
                           places=places_pagination.items,
                           pagination=places_pagination)

@app.route('/admin/places/<int:place_id>/edit')
@admin_required
def edit_place(place_id):
    """Страница редактирования заведения"""
    user = User.query.filter_by(username=session['username']).first()
    if user.role == 'trainee':
        return render_template('Error.html', error_code=403, error_message="Доступ запрещён"), 403

    place = Place.query.get_or_404(place_id)
    categories = ['Ресторан', 'Кафе', 'Магазин', 'Музей', 'Театр', 'Библиотека',
                  'Парк', 'Кинотеатр', 'Спортплощадка', 'Церковь', 'Гостиница', 'Иконка']

    return render_template('edit_place.html',
                           current_user=user,
                           place=place,
                           categories=categories)


@app.route('/admin/api/places/<int:place_id>', methods=['DELETE'])
@admin_required
def admin_delete_place(place_id):
    """API для удаления заведения"""
    try:
        user = User.query.filter_by(username=session['username']).first()
        # Запрещаем стажёрам удалять заведения
        if user.role == 'trainee':
            return render_template('Error.html', error_code=403, error_message="Недостаточно прав"), 403

        place = Place.query.get_or_404(place_id)
        db.session.delete(place)
        db.session.commit()

        return jsonify({'success': True, 'message': 'Заведение удалено'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/api/places/<int:place_id>', methods=['PUT'])
@admin_required
def admin_update_place(place_id):
    """API для обновления заведения"""
    try:
        user = User.query.filter_by(username=session['username']).first()
        # Запрещаем стажёрам редактировать заведения
        if user.role == 'trainee':
            return render_template('Error.html', error_code=403, error_message="Доступ запрещён"), 403

        place = Place.query.get_or_404(place_id)
        data = request.get_json()

        # Обновляем поля
        if 'title' in data:
            place.title = data['title'].strip()
        if 'description' in data:
            place.description = data['description'].strip()
        if 'category' in data:
            place.category = data['category']
            # Автоматически генерируем category_en
            category_mapping = {
                'Ресторан': 'restaurant', 'Кафе': 'cafe', 'Магазин': 'shop',
                'Музей': 'museum', 'Театр': 'theatre', 'Библиотека': 'library',
                'Парк': 'park', 'Кинотеатр': 'cinema', 'Спортплощадка': 'sports',
                'Церковь': 'church', 'Гостиница': 'hotel', 'Иконка': 'icon'
            }
            place.category_en = category_mapping.get(data['category'], 'other')
        if 'telephone' in data:
            place.telephone = data['telephone'].strip()
        if 'address' in data:
            place.address = data['address'].strip()
        if 'slug' in data:
            place.slug = data['slug'].strip()
        if 'tags' in data:
            place.tags = data['tags'].strip()

        db.session.commit()

        return jsonify({'success': True, 'message': 'Заведение обновлено'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/reviews')
@admin_required
def admin_reviews_page():
    """Страница управления отзывами"""
    user = User.query.filter_by(username=session['username']).first()
    if user.role == 'trainee':
        return render_template('Error.html', error_code=403, error_message="Доступ запрещён"), 403

    # Пагинация для отзывов
    page = request.args.get('page', 1, type=int)
    per_page = 20

    reviews_pagination = Review.query.order_by(Review.created_at.desc()).paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    # Добавляем информацию о местах к отзывам
    reviews_with_places = []
    for review in reviews_pagination.items:
        place = None
        if review.restaurant_id.isdigit():
            place = Place.query.get(int(review.restaurant_id))
        else:
            place = Place.query.filter_by(slug=review.restaurant_id).first()

        reviews_with_places.append({
            'review': review,
            'place_title': place.title if place else review.restaurant_id,
            'place_url': url_for('place_page_by_slug', category_en=place.category_en,
                                 slug=place.slug) if place and place.slug else url_for('restaurant_page',
                                                                                       id=place.id) if place else '#'
        })

    return render_template('admin_reviews.html',
                           current_user=user,
                           reviews_data=reviews_with_places,
                           pagination=reviews_pagination)

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


def migrate_categories_to_english():
    """Мигрирует категории на английские (после обновления структуры БД)"""
    CATEGORY_MAPPING = {
        'Ресторан': 'Restaurant',
        'Кафе': 'Cafe',
        'Магазин': 'Shop',
        'Музей': 'Museum',
        'Театр': 'Theatre',
        'Библиотека': 'Library',
        'Парк': 'Park',
        'Кинотеатр': 'Cinema',
        'Спортплощадка': 'Sports',
        'Церковь': 'Church',
        'Гостиница': 'Hotel',
        'Иконка': 'Icon'
    }

    try:
        places = Place.query.all()
        for place in places:
            if place.category in CATEGORY_MAPPING:
                place.category_en = CATEGORY_MAPPING[place.category]
                # Также генерируем slug если его нет
                if not place.slug and place.title:
                    place.slug = generate_slug(place.title)
                print(f"✅ {place.title}: {place.category} -> {place.category_en}")

        db.session.commit()
        print("✅ Категории мигрированы на английский!")

    except Exception as e:
        db.session.rollback()
        print(f"❌ Ошибка миграции: {e}")


def init_database():
    """Инициализация и обновление базы данных"""
    with app.app_context():
        try:
            # Создаем таблицы если их нет
            db.create_all()
            print("✅ База данных создана/проверена")

            # Проверяем есть ли рестораны
            restaurant_count = Place.query.filter_by(category='Ресторан').count()
            print(f"✅ Найдено ресторанов в базе: {restaurant_count}")

            # Мигрируем категории
            migrate_categories_to_english()

        except Exception as e:
            print(f"❌ Ошибка инициализации БД: {e}")

def fix_slug_duplicates():
    """Исправление дублирующихся slug"""
    with app.app_context():
        try:
            places = Place.query.all()
            used_slugs = set()

            for place in places:
                if not place.slug:
                    base_slug = generate_slug(place.title)
                    slug = base_slug
                    counter = 1

                    # Генерируем уникальный slug
                    while slug in used_slugs:
                        slug = f"{base_slug}-{counter}"
                        counter += 1

                    place.slug = slug
                    used_slugs.add(slug)
                    print(f"✅ {place.title}: slug={place.slug}")
                else:
                    used_slugs.add(place.slug)

            db.session.commit()
            print("✅ Все slug исправлены!")

        except Exception as e:
            db.session.rollback()
            print(f"❌ Ошибка исправления slug: {e}")


@app.route('/fix-slugs')
def fix_slugs_route():
    """Временный маршрут для исправления slug"""
    fix_slug_duplicates()
    return "Slug исправлены!"


@app.route('/fix-ratings')
def fix_ratings():
    """Принудительное обновление всех рейтингов"""
    try:
        places = Place.query.all()
        fixed_count = 0

        for place in places:
            # Обновляем статистику для этого места
            update_restaurant_stats(str(place.id))
            fixed_count += 1

        return jsonify({
            'success': True,
            'message': f'Обновлены рейтинги для {fixed_count} мест',
            'fixed_count': fixed_count
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        # Инициализация базы данных
        db.create_all()

        # Другие инициализации
        migrate_categories_to_english()
        check_review_table_structure()

    app.run(debug=True)