#!/usr/bin/env python3
""" basic_auth.py
"""

import base64
import binascii
from typing import Tuple, Optional, TypeVar

from models.user import User
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """ class to manage Basic Authentication
    """

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """extracts base64 from the authorization header
        """
        if authorization_header is None or isinstance(authorization_header, str) == False:
            return None
        if authorization_header.startswith("Basic "):

            return authorization_header[6:]

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """ returns decoded value of a Base64 string
        """
        if base64_authorization_header is None or isinstance(base64_authorization_header, str) == False:
            return None
        try:
            return base64.b64decode(base64_authorization_header).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> Tuple[Optional[str], Optional[str]]:
        """  returns user email and pasword from the Base64 decoded value
        """
        if decoded_base64_authorization_header is None or isinstance(decoded_base64_authorization_header, str) == False:
            return None, None
        if ":" in decoded_base64_authorization_header:
            user_pass = decoded_base64_authorization_header.split(":", 1)
            return user_pass[0], user_pass[1]
        else:
            return None, None

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """ returns the user instance based on her email and password
        """
        if user_email is None or user_pwd is None:
            return None
        if isinstance(user_email, str) == False or isinstance(user_pwd, str) == False:
            return None
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
            else:
                return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Overloads Auth and retrieves the User instance for a request
        """
        auth_header = self.authorization_header(request)
        base64_header = self.extract_base64_authorization_header(auth_header)
        decoded_base64_header = self.decode_base64_authorization_header(
            base64_header)
        user_credentials = self.extract_user_credentials(decoded_base64_header)
        return self.user_object_from_credentials(*user_credentials)
