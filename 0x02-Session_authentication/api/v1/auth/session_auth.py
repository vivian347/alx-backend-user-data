#!/usr/bin/env python3
""" session_auth.py
"""

import base64
import binascii
from typing import Tuple, Optional, TypeVar
import uuid

from models.user import User
from api.v1.auth.auth import Auth


class SessionAuth(Auth):
    """ class to manage session Authentication
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """ creates session id for a user_id
        """
        if not user_id or isinstance(user_id, str) is False:
            return None

        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """ return a User ID  based on a Session ID
        """
        if not session_id or isinstance(session_id, str) is False:
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """ return a User instance based on a cookie val
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        return User.get(user_id)

    def destroy_session(self, request=None):
        """ deletes the user session/logout
        """
        if request is None or self.session_cookie(request) is None:
            return False
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        if not user_id:
            return False
        del self.user_id_by_session_id[session_id]
        return True
    