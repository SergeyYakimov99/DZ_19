import calendar
import datetime

from constants import secret, algo
from service.user import UserService
import jwt


class AuthService:
    def __init__(self, user_service: UserService):
        self.user_service = user_service

    def generate_tokens(self, username, password, is_refresh=False):
        user = self.user_service.get_by_username(username)

        if not user:
            return False

        if not is_refresh:
            if not self.user_service.compare_passwords(password, user.password):
                return False

        data = {
            "username": user.username,
            "role": user.role
        }
        # генерируем access_token на 30 мин.
        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data["exp"] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, secret, algorithm=algo)

        # генерируем refresh_token на 130 дней.
        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data["exp"] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, secret, algorithm=algo)

        return {"access_token": access_token, "refresh_token": refresh_token}, 201

    def approve_refresh_token(self, refresh_token):
        data = jwt.decode(refresh_token, secret, algorithms=[algo])
        username = data['username']
        user = self.user_service.get_by_username(username)

        if not user:
            return False

        return self.generate_tokens(username, user.password, is_refresh=True)
