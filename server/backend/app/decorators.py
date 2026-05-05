
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from flask import Response, jsonify, request
from flask import current_app as app
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from app.utils import read_config
import jwt
import hashlib
from typing import Any, Callable, Optional, TypeVar, cast

auth = HTTPBasicAuth()
F = TypeVar("F", bound=Callable[..., Any])


@auth.verify_password
def check_creds(user: str, password: str) -> bool:
    """
        Check the credentials
        :return: :bool: if the authentication succeed.
    """
    if user == read_config(("backend", "login")) and check_password(password):
        return True
    return False


def check_password(password: str) -> bool:
    """
        Password hashes comparison (submitted and the config one)
        :return: True if there is a match between the two hases
    """
    if read_config(("backend", "password")) == hashlib.sha256(password.encode()).hexdigest():
        return True
    return False


def _verify_jwt_token(token: str) -> None:
    """
        Verify JWT signature + expiration.
        Raises jwt.InvalidTokenError (or subclasses) when invalid.
    """
    jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])


def require_header_token(f: F) -> F:
    """
        Check the JWT token validity in POST requests.
        :return: decorated method
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Token")
        if not token:
            return jsonify({"message": "Missing token"}), 401
        try:
            _verify_jwt_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "JWT verification failed"}), 403
        return f(*args, **kwargs)
    return cast(F, decorated)


def require_get_token(f: F) -> F:
    """
        Check the JWT token validity in GET requests.
        :return: decorated method
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get("token")
        if not token:
            return jsonify({"message": "Missing token"}), 401
        try:
            _verify_jwt_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "JWT verification failed"}), 403
        return f(*args, **kwargs)
    return cast(F, decorated)
