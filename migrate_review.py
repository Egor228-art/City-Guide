import sqlite3
import json
from datetime import datetime

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
        print(f"Существующие колонки: {columns}")

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

        # Обновляем значения для новых колонок, если нужно
        cursor.execute("UPDATE review SET user_ratings = '{}' WHERE user_ratings IS NULL")
        cursor.execute("UPDATE review SET likes = 0 WHERE likes IS NULL")
        cursor.execute("UPDATE review SET dislikes = 0 WHERE dislikes IS NULL")

        conn.commit()
        print("Миграция таблицы review завершена успешно!")

        # Проверяем результат
        cursor.execute("PRAGMA table_info(review)")
        final_columns = [column[1] for column in cursor.fetchall()]
        print(f"Колонки после миграции: {final_columns}")

    except Exception as e:
        print(f"Ошибка при миграции: {e}")
        conn.rollback()
        raise e
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_review_table()