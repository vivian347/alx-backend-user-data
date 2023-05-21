#!/usr/bin/env python3
"""flask app
"""

from flask import Flask, abort, jsonify, redirect, request
from auth import Auth

AUTH = Auth()

app = Flask(__name__)


@app.route('/', methods=['GET'], strict_slashes=False)
def payload():
    """returns a JSON payload"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users():
    """endpoint to register user
    """
    email = request.form.get('email')
    password = request.form.get('password')

    try:
        user = AUTH.register_user(email, password)
        return jsonify({
            'email': email,
            'message': 'user created'
        })
    except ValueError:
        return jsonify({
            'message': 'email already registered'
        }), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login():
    """create a new session for user"""
    email = request.form.get('email')
    password = request.form.get('password')
    valid_user = AUTH.valid_login(email, password)

    if not valid_user:
        abort(401)
    session_id = AUTH.create_session(email)
    response = jsonify({'email': email, 'message': 'logged in'})
    response.set_cookie('session_id', session_id)
    return response

@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout():
    """if user with session id exists
    destroy session and redirect user to '/'
    """
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)

    if session_id is None or user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect('/')

@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile():
    """checks if user exists"""
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)

    if session_id is None or user is None:
        abort(403)
    return jsonify({'email': user.email}), 200

@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token():
    """get's users reset_token"""
    email = request.form.get('email')
    user = AUTH.create_session(email)

    if not user:
        abort(403)

    token = AUTH.get_reset_password_token(email)
    return jsonify({'email': email, 'reset_token': token}), 200

@app.route('/reset_password', methods='PUT', strict_slashes=False)
def update_password():
    """reset users password"""
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')

    try:
        AUTH.update_password(reset_token, new_password)
    except Exception:
        abort(403)
    
    return({
        'email': email,
        'message': 'Password updated'
    }), 200



if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
