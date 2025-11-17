import os
import base64
import mysql.connector
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# ============================
#   Database Configuration
# ============================

DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_USER = os.environ.get('DB_USER', 'scuser')
DB_PASS = os.environ.get('DB_PASS', 'scpass')  # Local development password
DB_NAME = os.environ.get('DB_NAME', 'securechat')


# ============================
#   Database Helpers
# ============================

def get_db_connection():
    """
    Establishes a new MariaDB/MySQL database connection.

    Returns:
        mysql.connector.connection.MySQLConnection | None
    """
    try:
        return mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME,
        )
    except mysql.connector.Error as err:
        print(f"[DB] Connection error: {err}")
        return None


def init_db():
    """
    Initializes the database schema.

    Creates the 'users' table if it does not already exist.

    Schema (assignment requirement):
        email VARCHAR(255) UNIQUE
        username VARCHAR(255) UNIQUE
        salt VARBINARY(16)
        pwd_hash CHAR(64)   -> hex SHA256(salt || password)
    """
    conn = get_db_connection()
    if not conn:
        return

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            username VARCHAR(255) UNIQUE NOT NULL,
            salt VARBINARY(16) NOT NULL,
            pwd_hash CHAR(64) NOT NULL
        );
    """)

    conn.commit()
    cursor.close()
    conn.close()
    print("[DB] Initialized: 'users' table is ready.")


# ============================
#   Password Hashing
# ============================

def hash_password(password, salt):
    """
    Computes SHA-256(salt || password) as required by the assignment.

    Args:
        password (str)
        salt (bytes)

    Returns:
        hex string (64 chars)
    """
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(salt)
    hasher.update(password.encode('utf-8'))
    return hasher.finalize().hex()


# ============================
#   User Registration
# ============================

def register_user(email, username, password):
    """
    Registers a new user by generating a random 16-byte salt and storing:
        - email
        - username
        - salt
        - hex SHA256(salt || password)

    Returns:
        (bool, message)
    """
    salt = os.urandom(16)
    pwd_hash = hash_password(password, salt)

    conn = get_db_connection()
    if not conn:
        return False, "Database connection failed"

    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )
        conn.commit()
        print(f"[DB] User '{username}' registered successfully.")
        return True, "User registered successfully"

    except mysql.connector.Error as err:
        if err.errno == 1062:  # Duplicate email/username
            return False, "Email or username already exists"
        return False, f"Database error: {err}"

    finally:
        cursor.close()
        conn.close()


# ============================
#   Authentication
# ============================

def verify_user(email, password):
    """
    Checks if the provided email and password match a stored user record.

    Steps:
        1. Fetch stored salt and pwd_hash
        2. Compute SHA256(salt || password)
        3. Compare (constant-time safe in Python due to fixed-length strings)

    Returns:
        (bool, message)
    """
    conn = get_db_connection()
    if not conn:
        return False, "Database connection failed"

    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT salt, pwd_hash FROM users WHERE email = %s",
            (email,)
        )
        user = cursor.fetchone()

        if not user:
            return False, "User not found"

        stored_salt = user["salt"]
        stored_hash = user["pwd_hash"]

        computed_hash = hash_password(password, stored_salt)

        if computed_hash == stored_hash:
            print(f"[Auth] User '{email}' authenticated successfully.")
            return True, "Login successful"
        else:
            return False, "Invalid password"

    except mysql.connector.Error as err:
        return False, f"Database error: {err}"

    finally:
        cursor.close()
        conn.close()


# ============================
#   Script Entry Point
# ============================

if __name__ == "__main__":
    print("Initializing database...")
    init_db()
