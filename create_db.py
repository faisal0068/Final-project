import sqlite3
import bcrypt  # For password hashing

def create_database():
    try:
        # Connect to the SQLite database (this will create the database if it doesn't exist)
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Create the 'users' table if it does not exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
        ''')

        # Commit changes and close connection
        conn.commit()
        print("Database and users table created successfully.")

    except sqlite3.Error as e:
        print(f"An error occurred while interacting with the database: {e}")
    
    finally:
        # Ensure the connection is closed even if there was an error
        if conn:
            conn.close()

def create_admin_user():
    """This function creates an admin user with a hashed password."""
    try:
        # Example of creating a hashed password for an admin user
        hashed_password = bcrypt.hashpw('adminpassword'.encode('utf-8'), bcrypt.gensalt())

        # Connect to the database
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Check if the admin user already exists
        cursor.execute("SELECT * FROM users WHERE role='admin'")
        existing_admin = cursor.fetchone()

        if not existing_admin:
            # Insert an admin user if one does not exist
            cursor.execute('''
            INSERT INTO users (username, email, password, role)
            VALUES (?, ?, ?, ?)
            ''', ('admin', 'admin@example.com', hashed_password, 'admin'))
            conn.commit()
            print("Admin user created successfully.")
        else:
            print("Admin user already exists.")

    except sqlite3.Error as e:
        print(f"An error occurred while creating the admin user: {e}")
    
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    # Create the database and users table
    create_database()

    # Optionally, create an admin user (only if it doesn't exist already)
    create_admin_user()
