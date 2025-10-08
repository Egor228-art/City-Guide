import sqlite3

def migrate_place_table():
    """Миграция таблицы place - добавление новых столбцов"""
    try:
        conn = sqlite3.connect('instance/database.db')
        cursor = conn.cursor()

        # Проверяем существующие столбцы
        cursor.execute("PRAGMA table_info(place)")
        columns = [column[1] for column in cursor.fetchall()]
        print(f"Существующие колонки: {columns}")

        # Добавляем отсутствующие колонки
        new_columns = [
            ('tags', 'TEXT'),
            ('slug', 'VARCHAR(100)'),
            ('latitude', 'FLOAT'),
            ('longitude', 'FLOAT'),
            ('working_hours', 'TEXT'),
            ('menu', 'TEXT')
        ]

        for column_name, column_type in new_columns:
            if column_name not in columns:
                print(f"Добавляем колонку {column_name}...")
                cursor.execute(f"ALTER TABLE place ADD COLUMN {column_name} {column_type}")

        conn.commit()
        print("Миграция таблицы place завершена успешно!")

        # Показываем результат
        cursor.execute("PRAGMA table_info(place)")
        final_columns = [column[1] for column in cursor.fetchall()]
        print(f"Финальные колонки: {final_columns}")

    except Exception as e:
        print(f"Ошибка при миграции: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_place_table()