#!/usr/bin/env python3
"""flask app
"""

from flask import Flask, abort, jsonify, request
from auth import Auth

AUTH = Auth()

app = Flask(__name__)

@app.route('/', methods=['GET'])
def payload():
    """returns a JSON payload"""
    return jsonify({"message": "Bienvenue"})

@app.route('/users', methods=['POST'])
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

@app.route('/sessions', methods=['POST'])
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")