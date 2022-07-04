import jwt
from flask import request, abort
from constants import secret, algo


def auth_requered(func):
    """ Декоратор на авторизацию"""

    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        token = request.headers['Authorization']
        try:
            jwt.decode(token, secret, algorithms=[algo])
        except Exception as e:
            print(f"JWT decode error {e}")
            abort(401)
        return func(*args, **kwargs)

    return wrapper


def admin_requered(func):
    """ Декоратор на роль Админа"""

    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        token = request.headers['Authorization']
        try:
            data = jwt.decode(token, secret, algorithms=[algo])
        except Exception as e:
            print(f"JWT decode error {e}")
            abort(401)
        else:
            if data["role"] == "admin":
                return func(*args, **kwargs)
        abort(403)

    return wrapper
