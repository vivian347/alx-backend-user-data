#!/usr/bin/env python3
"""auth file
"""

import uuid
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """takes in a password and returns a salted
    hash of the password
    """
    encrypted_pwd = password.encode('utf-8')
    return bcrypt.hashpw(encrypted_pwd, bcrypt.gensalt())


def _generate_uuid() -> str:
    """return a string rep of a new UUID"""
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """initialize class Auth"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """hashes password and saves user to db"""
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """locate user by email an check if password matches"""
        try:
            user = self._db.find_user_by(email=email)
            encrypted_pwd = password.encode('utf-8')
            return bcrypt.checkpw(encrypted_pwd, user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id
