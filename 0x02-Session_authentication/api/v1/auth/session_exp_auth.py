#!/usr/bin/env python3
""" session_exp_auth.py
"""

from models.user import User
import datetime
from os import getenv
from api.v1.auth.session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """ class to manage session expiration
    """
    def __init__(self) -> None:
        """Ovverird init"""
        try:
            self.session_duration = int(getenv('SESSION_DURATION'))
        except:
            self.session_duration = 0

    def create_session(self, user_id = None):
        """ overload create_session
        """
        try:
            session_id = super().create_session(user_id)
        except Exception:
            return None
        session_dictionary = {
            'user_id': user_id,
            'created_at': datetime.now()
        }
        self.user_id_by_session_id[session_id] = session_dictionary
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """Overload user_id_for_session_id
        """
        if session_id is None:
            return None
        session_dict = self.user_id_by_session_id.get('session_id')
        if not session_dict or 'created_at' not in session_dict:
            return None
        
        if self.session_duration <= 0:
            return session_dict.get('user_id')
        created_time = session_dict.get('created_at')
        elapsed = datetime.timedelta(seconds=self.session_duration)
        if created_time + elapsed < datetime.now():
            return None
        else:
            return session_dict.get('user_id')
