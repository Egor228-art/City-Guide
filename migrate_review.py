import sqlite3


def fix_role_field():
    conn = sqlite3.connect('instance/database.db')
    cursor = conn.cursor()

    print("🔧 Исправление поля role...")

    try:
        # Проверяем текущий тип поля role
        cursor.execute("PRAGMA table_info(user)")
        columns = cursor.fetchall()
        role_column = next((col for col in columns if col[1] == 'role'), None)

        if role_column:
            print(f"Текущий тип role: {role_column[2]}")

            # Если тип неправильный, пересоздаем таблицу
            if role_column[2] != 'VARCHAR(50)':
                print("Пересоздаем таблицу user...")

                # Создаем временную таблицу
                cursor.execute("""
                    CREATE TABLE user_temp (
                        id INTEGER PRIMARY KEY,
                        username VARCHAR(150) NOT NULL UNIQUE,
                        password VARCHAR(150) NOT NULL,
                        role VARCHAR(50) DEFAULT 'trainee',
                        created_at TEXT,
                        last_login TEXT
                    )
                """)

                # Копируем данные
                cursor.execute("""
                    INSERT INTO user_temp (id, username, password, role, created_at, last_login)
                    SELECT id, username, password, role, created_at, last_login FROM user
                """)

                # Удаляем старую таблицу
                cursor.execute("DROP TABLE user")

                # Переименовываем временную таблицу
                cursor.execute("ALTER TABLE user_temp RENAME TO user")

                print("✅ Таблица user пересоздана")

        conn.commit()
        print("✅ Поле role исправлено")

    except Exception as e:
        print(f"❌ Ошибка: {e}")
        conn.rollback()
    finally:
        conn.close()


if __name__ == "__main__":
    fix_role_field()