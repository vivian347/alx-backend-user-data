#!/usr/bin/env python3
""" encrypt_password
"""
import bcrypt

def hash_password(password: str) -> bytes:
    encoded_pwd = password.encode('utf-8')
    return bcrypt.hashpw(encoded_pwd, bcrypt.gensalt())

def is_valid(hashed_password: bytes, password: str) -> bool:
    encoded_pwd = password.encode('utf-8')
    if bcrypt.checkpw(encoded_pwd, hashed_password):
        return True
    else:
        return False