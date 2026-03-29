# ------------------------------------------------------
# 🔐 Authentifizierung, E-Mail-Verifizierung & Passwort-Reset
# ------------------------------------------------------
from flask import Blueprint, request, jsonify, current_app
from Backend.db import SessionLocal
from Backend.models import User, BlacklistedToken
import jwt, datetime, os, bcrypt
from flask_mail import Message

auth_bp = Blueprint("auth_bp", __name__)
SECRET_KEY = os.getenv("SECRET_KEY", "change_me")


# ------------------------------------------------------
# 🔓 Optionales Token-Decoding
# ------------------------------------------------------
def decode_token_optional(request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ")[1]

    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return data.get("user_id")
    except jwt.InvalidTokenError:
        return None


# ------------------------------------------------------
# 🔧 Token prüfen (mit Blacklist)
# ------------------------------------------------------
def require_token(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "missing or invalid token"}), 401

        token = auth_header.split(" ")[1]

        # Token in Blacklist?
        session = SessionLocal()
        blocked = session.query(BlacklistedToken).filter_by(token=token).first()
        if blocked:
            return jsonify({"error": "token invalidated (logout)"}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_id = data.get("user_id")
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401

        return func(*args, **kwargs)
    return wrapper


# ------------------------------------------------------
# 🚪 Logout (Token → Blacklist)
# ------------------------------------------------------
@auth_bp.route("/api/logout", methods=["POST"])
@require_token
def logout_user():
    session = SessionLocal()
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.split(" ")[1]

    session.add(BlacklistedToken(token=token))
    session.commit()

    return jsonify({"message": "logout successful"}), 200


# ------------------------------------------------------
# 👤 Registrierung (mit E-Mail-Verifizierung)
# ------------------------------------------------------
@auth_bp.route("/api/register", methods=["POST"])
def register_user():
    session = SessionLocal()
    data = request.get_json() or {}
    username, email, password = data.get("username"), data.get("email"), data.get("password")

    if not username or not email or not password:
        return jsonify({"error": "username, email, and password required"}), 400

    if session.query(User).filter((User.username == username) | (User.email == email)).first():
        return jsonify({"error": "user already exists"}), 409

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user = User(username=username, email=email, password_hash=hashed)
    session.add(user)
    session.commit()

    # Verifizierungs-E-Mail senden
    try:
        from app import mail
        token = jwt.encode(
            {"email": email, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
            SECRET_KEY,
            algorithm="HS256"
        )
        verify_link = f"http://localhost:5001/api/verify_email?token={token}"

        with current_app.app_context():
            msg = Message(
                subject="Bitte bestätige deine E-Mail-Adresse",
                sender=os.getenv("MAIL_DEFAULT_SENDER", "no-reply@websecscan.com"),
                recipients=[email],
                body=(
                    f"Hallo {username},\n\n"
                    f"Bitte bestätige deine E-Mail:\n{verify_link}\n\n"
                    f"Viele Grüße,\nWebSecScan-Team"
                )
            )
            mail.send(msg)
    except Exception as e:
        print("⚠️ Fehler beim E-Mail-Versand:", e)

    return jsonify({"message": "user registered successfully. verification email sent"}), 201


# ------------------------------------------------------
# 🔐 Login
# ------------------------------------------------------
@auth_bp.route("/api/login", methods=["POST"])
def login_user():
    session = SessionLocal()
    data = request.get_json() or {}
    username, password = data.get("username"), data.get("password")

    if not username or not password:
        return jsonify({"error": "missing credentials"}), 400

    user = session.query(User).filter(User.username == username).first()
    if not user or not bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
        return jsonify({"error": "invalid username or password"}), 401

    if not user.active:
        return jsonify({"error": "email not verified"}), 403

    token = jwt.encode(
        {"user_id": user.id, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=12)},
        SECRET_KEY,
        algorithm="HS256"
    )

    return jsonify({
        "access_token": token,
        "user": {"id": user.id, "username": user.username, "email": user.email}
    }), 200


# ------------------------------------------------------
# 👤 Profil abrufen
# ------------------------------------------------------
@auth_bp.route("/api/profile", methods=["GET"])
@require_token
def user_profile():
    session = SessionLocal()
    user = session.query(User).get(request.user_id)
    if not user:
        return jsonify({"error": "user not found"}), 404

    return jsonify({
        "username": user.username,
        "email": user.email,
        "created_at": user.created_at.isoformat(),
        "confirmed_at": user.confirmed_at.isoformat() if user.confirmed_at else None
    })


# ------------------------------------------------------
# ✉️ E-Mail bestätigen
# ------------------------------------------------------
@auth_bp.route("/api/verify_email", methods=["GET"])
def verify_email():
    token = request.args.get("token")
    session = SessionLocal()

    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email = data.get("email")
        user = session.query(User).filter_by(email=email).first()

        if not user:
            return jsonify({"error": "user not found"}), 404

        user.active = True
        user.confirmed_at = datetime.datetime.utcnow()
        session.commit()

        return jsonify({"message": "E-Mail erfolgreich bestätigt!"}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "verification link expired"}), 400
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid token"}), 400


# ------------------------------------------------------
# 🔥 NEU: Passwort zurücksetzen (Schritt 1 – Reset-Mail senden)
# ------------------------------------------------------
@auth_bp.route("/api/forgot_password", methods=["POST"])
def forgot_password():
    session = SessionLocal()
    data = request.get_json() or {}
    email = data.get("email")

    if not email:
        return jsonify({"error": "email required"}), 400

    user = session.query(User).filter_by(email=email).first()
    if not user:
        return jsonify({"error": "user not found"}), 404

    # Reset-Token erstellen (30 Minuten gültig)
    token = jwt.encode(
        {
            "email": user.email,
            "action": "reset_password",
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        },
        SECRET_KEY,
        algorithm="HS256"
    )

    reset_link = f"https://localhost:5001/reset_password?token={token}"

    # E-Mail senden (Mailtrap)
    try:
        from app import mail
        with current_app.app_context():
            msg = Message(
                subject="Passwort zurücksetzen",
                sender=os.getenv("MAIL_DEFAULT_SENDER"),
                recipients=[email],
                body=(
                    f"Hallo {user.username},\n\n"
                    f"Klicke auf den Link, um dein Passwort zurückzusetzen:\n"
                    f"{reset_link}\n\n"
                    f"Der Link ist 30 Minuten gültig.\n"
                )
            )
            mail.send(msg)

    except Exception as e:
        print("E-Mail Fehler:", e)

    return jsonify({"message": "reset email sent"}), 200


# ------------------------------------------------------
# 🔥 NEU: Passwort ändern (Schritt 2)
# ------------------------------------------------------
@auth_bp.route("/api/reset_password", methods=["POST"])
def reset_password():
    session = SessionLocal()
    data = request.get_json() or {}

    token = data.get("token")
    new_password = data.get("new_password")

    if not token or not new_password:
        return jsonify({"error": "token and new_password required"}), 400

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        if decoded.get("action") != "reset_password":
            return jsonify({"error": "invalid token action"}), 400

        email = decoded.get("email")
        user = session.query(User).filter_by(email=email).first()

        if not user:
            return jsonify({"error": "user not found"}), 404

        # Passwort ändern
        user.set_password(new_password)
        session.commit()

        return jsonify({"message": "password updated"}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "reset token expired"}), 400
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid token"}), 400
