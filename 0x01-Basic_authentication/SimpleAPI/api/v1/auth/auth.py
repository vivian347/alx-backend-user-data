#!/usr/bin/env python3
""" auth.py
"""

from typing import List, TypeVar
from flask import request


class Auth:
    """class to manage API authentication
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """determines whether userrequires authentication
        """
        if path is None:
            return True
        if excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path.endswith("/"):
            path = path[:-1]
        for excluded_path in excluded_paths:
            if excluded_path.endswith("/") or excluded_path.endswith('*'):
                excluded_path = excluded_path[:-1]
            if path == excluded_path:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """ method to define the authorization header
        """
        if request is None:
            return None

        if 'Authorization' in request.headers:
            return request.headers['Authorization']
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ determines the current user
        """
        return None
