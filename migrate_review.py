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
                CREATE TABLE place (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title VARCHAR(100) NOT NULL,
                    description TEXT NOT NULL,
                    tags TEXT,
                    telephone VARCHAR(15) NOT NULL,
                    address VARCHAR(200) NOT NULL,
                    image_path VARCHAR(200) NOT NULL,
                    category VARCHAR(15) NOT NULL
                )    
            """)
            print("Таблица place создана успешно!")
            conn.commit()
            conn.close()
            return

        print("Таблица place существует. Начинаем миграцию...")

        # Проверяем существующие столбцы
        cursor.execute("PRAGMA table_info(place)")
        columns = [column[1] for column in cursor.fetchall()]
        print(f"Существующие колонки: {columns}")

        # Добавляем отсутствующие колонки
        new_columns = [
            ('tags', 'TEXT'),
        ]

        for column_name, column_type in new_columns:
            if column_name not in columns:
                print(f"Добавляем колонку {column_name}...")
                cursor.execute(f"ALTER TABLE place ADD COLUMN {column_name} {column_type}")

        # Обновляем значения для новых колонок, если нужно
        cursor.execute("UPDATE place SET tags = 0 WHERE likes IS NULL")

        conn.commit()
        print("Миграция таблицы place завершена успешно!")

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