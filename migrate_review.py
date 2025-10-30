import sqlite3
import os


def migrate_menu_field():
    """Миграция для замены поля menu на menu_pdf_path"""

    conn = sqlite3.connect('instance/database.db')
    cursor = conn.cursor()

    print("🔧 Начинаем миграцию поля menu -> menu_pdf_path...")

    try:
        # Проверяем текущую структуру таблицы place
        cursor.execute("PRAGMA table_info(place)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]

        print(f"Текущие колонки в таблице place: {column_names}")

        # Проверяем существование поля menu
        if 'menu' in column_names:
            print("✅ Найдено поле menu")

            # Проверяем существует ли уже menu_pdf_path
            if 'menu_pdf_path' not in column_names:
                print("🔄 Добавляем новое поле menu_pdf_path...")

                # Добавляем новое поле
                cursor.execute("ALTER TABLE place ADD COLUMN menu_pdf_path VARCHAR(255)")
                print("✅ Поле menu_pdf_path добавлено")

                # Очищаем старое поле menu (по вашему требованию)
                print("🔄 Очищаем старое поле menu...")
                cursor.execute("UPDATE place SET menu = '{}'")
                print("✅ Поле menu очищено")

            else:
                print("ℹ️ Поле menu_pdf_path уже существует")

        else:
            print("ℹ️ Поле menu не найдено в таблице")

            # Если menu нет, но нужно добавить menu_pdf_path
            if 'menu_pdf_path' not in column_names:
                print("🔄 Добавляем поле menu_pdf_path...")
                cursor.execute("ALTER TABLE place ADD COLUMN menu_pdf_path VARCHAR(255)")
                print("✅ Поле menu_pdf_path добавлено")

        # Проверяем результат
        cursor.execute("PRAGMA table_info(place)")
        final_columns = cursor.fetchall()
        print("📊 Итоговая структура таблицы place:")
        for col in final_columns:
            print(f"  - {col[1]} ({col[2]})")

        conn.commit()
        print("✅ Миграция успешно завершена!")

    except Exception as e:
        print(f"❌ Ошибка при миграции: {e}")
        conn.rollback()
        import traceback
        traceback.print_exc()

    finally:
        conn.close()


def verify_migration():
    """Проверка результатов миграции"""

    conn = sqlite3.connect('instance/database.db')
    cursor = conn.cursor()

    try:
        print("\n🔍 Проверка результатов миграции...")

        # Проверяем структуру
        cursor.execute("PRAGMA table_info(place)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]

        print("✅ Текущие колонки в таблице place:")
        for col in columns:
            print(f"  - {col[1]} ({col[2]})")

        # Проверяем данные
        cursor.execute("SELECT id, title, menu, menu_pdf_path FROM place LIMIT 5")
        sample_data = cursor.fetchall()

        print("\n📋 Пример данных:")
        for row in sample_data:
            print(f"  ID {row[0]}: {row[1]}")
            print(f"    menu: {row[2][:50]}...")  # Показываем только начало
            print(f"    menu_pdf_path: {row[3]}")
            print()

    except Exception as e:
        print(f"❌ Ошибка при проверке: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    print("🚀 Запуск миграции поля menu...")
    migrate_menu_field()
    verify_migration()
    print("🎉 Миграция завершена!")