import calendar
import datetime
import jwt

from flask import request, abort
from flask_restx import Namespace, Resource

from constants import secret, algo
from dao.model.user import User
from implemented import auth_service
from setup_db import db

auth_ns = Namespace('auth')

@auth_ns.route('/')
class AuthView(Resource):
    def post(self):
        req_json = request.json
        username = req_json.get("username")
        password = req_json.get("password")
        if not (username or password):
            return "необходимо имя и пароль", 400
        tokens = auth_service.generate_tokens(username, password)
        if tokens:
            return tokens
        else:
            return "Ошибка в запросе", 400



    def put(self):
        req_json = request.json
        refresh_token = req_json.get("refresh_token")
        if not refresh_token:
            return " Не задан токен", 400
        tokens = auth_service.approve_refresh_token(refresh_token)
        if tokens:
            return tokens
        else:
            return "Ошибка в запросе", 400

