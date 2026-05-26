import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "database.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;

        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    UNIQUE NOT NULL,
            password TEXT    NOT NULL,
            role     TEXT    NOT NULL DEFAULT 'user'
        );

        CREATE TABLE notes (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id  INTEGER NOT NULL,
            title    TEXT    NOT NULL,
            content  TEXT    NOT NULL
        );
    """)

    c.execute(
        "INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'REDACTED', 'admin')"
    )
    c.execute(
        "INSERT INTO users (id, username, password, role) VALUES (2, 'alice', 'alice123', 'user')"
    )
    c.execute(
        "INSERT INTO users (id, username, password, role) VALUES (3, 'bob', 'bob456', 'user')"
    )

    c.execute(
        "INSERT INTO notes (id, user_id, title, content) VALUES (1, 1, 'Admin Secret', 'REDACTED')"
    )
    c.execute(
        "INSERT INTO notes (id, user_id, title, content) VALUES (2, 2, 'Alice grocery list', 'Milk, eggs, bread.')"
    )
    c.execute(
        "INSERT INTO notes (id, user_id, title, content) VALUES (3, 3, 'Bob todo', 'Finish the report.')"
    )

    conn.commit()
    conn.close()
    print("[db] Database initialised and seeded.")


if __name__ == "__main__":
    init_db()