#!/usr/bin/env python3
"""
Миграция таблицы place - добавление столбца additional_images
Запуск: python migrate_place_table.py
"""

import os
import sys
import sqlite3
from datetime import datetime


def get_db_path():
    """Получение пути к базе данных"""
    db_paths = [
        'instance/database.db',
        'database.db',
        '../instance/database.db'
    ]

    for path in db_paths:
        if os.path.exists(path):
            print(f"✅ Найдена база данных: {path}")
            return path

    print("❌ База данных не найдена!")
    return None


def backup_database(db_path):
    """Создание резервной копии базы данных"""
    backup_path = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    try:
        import shutil
        shutil.copy2(db_path, backup_path)
        print(f"✅ Создана резервная копия: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"❌ Ошибка создания резервной копии: {e}")
        return None


def check_column_exists(cursor, table_name, column_name):
    """Проверка существования столбца"""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [column[1] for column in cursor.fetchall()]
    return column_name in columns


def migrate_place_table():
    """Основная функция миграции"""
    print("🚀 Начало миграции таблицы place...")

    # Получаем путь к базе данных
    db_path = get_db_path()
    if not db_path:
        return False

    # Создаем резервную копию
    backup_path = backup_database(db_path)
    if not backup_path:
        print("❌ Продолжение без резервной копии невозможно!")
        return False

    try:
        # Подключаемся к базе данных
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        print("📊 Проверка текущей структуры таблицы place...")

        # Проверяем существование таблицы place
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='place'")
        if not cursor.fetchone():
            print("❌ Таблица 'place' не существует!")
            return False

        # Проверяем существование столбца additional_images
        if check_column_exists(cursor, 'place', 'additional_images'):
            print("✅ Столбец 'additional_images' уже существует")
            return True

        print("🔧 Добавление нового столбца 'additional_images'...")

        # Добавляем новый столбец
        cursor.execute("ALTER TABLE place ADD COLUMN additional_images JSON DEFAULT '[]'")

        # Проверяем успешность добавления
        if check_column_exists(cursor, 'place', 'additional_images'):
            print("✅ Столбец 'additional_images' успешно добавлен")
        else:
            print("❌ Не удалось добавить столбец 'additional_images'")
            return False

        # Проверяем данные в таблице
        cursor.execute("SELECT COUNT(*) FROM place")
        total_places = cursor.fetchone()[0]
        print(f"📈 Всего записей в таблице place: {total_places}")

        # Проверяем, что новый столбец работает корректно
        cursor.execute("SELECT id, title, additional_images FROM place LIMIT 5")
        sample_data = cursor.fetchall()

        print("📋 Пример данных после миграции:")
        for row in sample_data:
            print(f"   ID: {row[0]}, Название: {row[1]}, Доп. изображения: {row[2]}")

        # Сохраняем изменения
        conn.commit()
        print("💾 Изменения успешно сохранены")

        # Проверяем структуру таблицы после миграции
        print("\n🔍 Итоговая структура таблицы place:")
        cursor.execute("PRAGMA table_info(place)")
        columns = cursor.fetchall()
        for column in columns:
            print(f"   {column[1]} ({column[2]}) - {'NULL' if column[3] else 'NOT NULL'}")

        conn.close()
        print("\n🎉 Миграция успешно завершена!")
        return True

    except sqlite3.Error as e:
        print(f"❌ Ошибка SQLite при миграции: {e}")
        # Восстанавливаем из резервной копии при ошибке
        try:
            import shutil
            shutil.copy2(backup_path, db_path)
            print("✅ База данных восстановлена из резервной копии")
        except Exception as restore_error:
            print(f"❌ Ошибка восстановления из резервной копии: {restore_error}")
        return False

    except Exception as e:
        print(f"❌ Неожиданная ошибка при миграции: {e}")
        return False


def verify_migration():
    """Проверка успешности миграции"""
    print("\n🔎 Проверка результатов миграции...")

    db_path = get_db_path()
    if not db_path:
        return False

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Проверяем существование столбца
        if not check_column_exists(cursor, 'place', 'additional_images'):
            print("❌ Столбец 'additional_images' не найден после миграции!")
            return False

        # Проверяем, что столбец может принимать данные
        test_data = '["image1.jpg", "image2.jpg"]'
        cursor.execute("UPDATE place SET additional_images = ? WHERE id = (SELECT id FROM place LIMIT 1)", (test_data,))
        cursor.execute("SELECT additional_images FROM place WHERE additional_images IS NOT NULL LIMIT 1")
        result = cursor.fetchone()

        if result and result[0] == test_data:
            print("✅ Столбец 'additional_images' работает корректно")
        else:
            print("❌ Проблема с записью/чтением данных в столбец 'additional_images'")
            return False

        # Откатываем тестовые данные
        cursor.execute("UPDATE place SET additional_images = '[]' WHERE additional_images = ?", (test_data,))
        conn.commit()
        conn.close()

        print("✅ Проверка миграции успешно пройдена!")
        return True

    except Exception as e:
        print(f"❌ Ошибка при проверке миграции: {e}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("МИГРАЦИЯ ТАБЛИЦЫ PLACE")
    print("Добавление столбца: additional_images")
    print("=" * 60)

    # Выполняем миграцию
    success = migrate_place_table()

    if success:
        # Проверяем результаты
        verify_migration()
        print("\n✅ Миграция завершена успешно!")
        sys.exit(0)
    else:
        print("\n❌ Миграция завершена с ошибками!")
        sys.exit(1)