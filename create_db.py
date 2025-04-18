import sqlite3

# Connect to your database
conn = sqlite3.connect('your_database.db')  # Replace with your DB file name
cursor = conn.cursor()

# Create users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
)
''')

conn.commit()
conn.close()

print("Database and users table created successfully.")
