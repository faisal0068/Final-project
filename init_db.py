import sqlite3

connection = sqlite3.connect('database.db')  # Replace with your actual DB name
cursor = connection.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user'
    )
''')

connection.commit()
connection.close()

print("Database initialized successfully.")
