from flask import Flask, render_template, request, redirect, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "supersecret"

DB_PATH = "users.db"

# --- Глобальный список сообщений ---
messages = []

# --- Инициализация базы данных ---
def init_db():
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE users(
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT
            )
        """)
        conn.commit()
        conn.close()

init_db()

# --- Главная ---
@app.route("/")
def index():
    return redirect("/login")

# --- Регистрация ---
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            error = "Введите логин и пароль!"
        else:
            hashed = generate_password_hash(password)
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            try:
                c.execute("INSERT INTO users(username, password) VALUES (?, ?)", (username, hashed))
                conn.commit()
                conn.close()
                return redirect("/login")
            except sqlite3.IntegrityError:
                conn.close()
                error = "Пользователь уже существует!"
    return render_template("register.html", error=error)

# --- Логин ---
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            error = "Введите логин и пароль!"
        else:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE username=?", (username,))
            user = c.fetchone()
            conn.close()
            if user and check_password_hash(user[0], password):
                session["logged_in"] = True
                session["username"] = username
                return redirect("/messages")
            else:
                error = "Неправильный логин или пароль!"
    return render_template("login.html", error=error)

# --- Выход ---
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# --- Страница чата ---
@app.route("/messages", methods=["GET", "POST"])
def chat():
    if not session.get("logged_in"):
        return redirect("/login")

    if request.method == "POST":
        reply = request.form.get("reply")
        if reply:
            safe_text = escape(reply)
            messages.append({"from": session["username"], "text": safe_text})
            if len(messages) > 100:
                messages.pop(0)

    return render_template("messages.html", messages=messages, user=session["username"])

# --- AJAX: получение сообщений ---
@app.route("/get_messages")
def get_messages():
    if not session.get("logged_in"):
        return jsonify([])
    return jsonify(messages)

if __name__ == "__main__":
    app.run(debug=True)
