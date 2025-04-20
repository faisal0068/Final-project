import sqlite3
import os
from config import Config  # Assuming you have a Config class to manage paths

# Use Config or dynamically set the path for your database
db_path = os.path.join(os.getcwd(), 'database.db')  # Example of dynamic path

# Connect to SQLite database (it will create the database file if it doesn't exist)
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create the users table if it doesn't exist, now including a created_at timestamp
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

# Commit the changes and close the connection
conn.commit()
conn.close()

print(f"✅ Database '{db_path}' and users table created successfully.")
