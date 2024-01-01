import base64
import hashlib
import hmac
import json
from typing import Optional

from fastapi import Cookie, FastAPI, Form
from fastapi.responses import Response


app = FastAPI()

users = {
    "test": {
        "name": "Anonymous",
        "password": "a48f0e30e0027904ac235297314af1a20bcefd2587356c0a2ad42d06dd931a8e",  # 12345678
        "balance": 100
    },
    "lapindanil22": {
        "name": "Danil",
        "password": "6eba84da04cd6e5973c15b8a778518278e9412a5b8e1d1ecbfbd6cf2113e2076",  # rfkbyf886
        "balance": 9812
    }
}

SECRET_KEY = "ad9baac7fa5bc374504008d4f9ea8f57e13f4e76448b7bc024f4fb4c73a3a71e"
PASSWORD_SALT = "fd4df99d463cd084e9aaf0997b350cbeb738f9338bee3355c9d331aaaf6394fc"


def sign_data(data: str) -> str:
    """Returns signature of data"""
    return hmac.new(SECRET_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    """Returns username from signature or None, if signature broken"""
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    if not hmac.compare_digest(sign_data(username), sign):
        return None
    return username


def verify_password(username: str, password: str) -> bool:
    """Verifies credentials of user with existing username"""
    password_hash = users[username]["password"]
    return hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest() == password_hash


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open("templates/index.html", "r") as file:
        my_index_page = file.read()

    if not username:
        return Response(my_index_page)

    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(my_index_page)
        response.delete_cookie(key="username")
        return response

    try:
        users[valid_username]
    except KeyError:
        response = Response(my_index_page)
        response.delete_cookie(key="username")
        return response

    return Response(json.dumps({
        "success": True,
        "message": f"Hello, {users[valid_username]["name"]}!"
    }), media_type="application/json")


@app.post("/login")
def process_auth_page(username: Optional[str] = Form(default=None),
                      password: Optional[str] = Form(default=None)):
    if not username or not password:
        with open("templates/index.html", "r") as file:
            my_index_page = file.read()
        return Response(my_index_page)

    user = users.get(username)
    if not user:
        return Response(json.dumps({
            "success": False,
            "message": "User not found"
        }), media_type="application/json")

    if not verify_password(username, password):
        return Response(json.dumps({
            "success": False,
            "message": "Invalid password"
        }), media_type="application/json")

    response = Response(json.dumps({
        "success": False,
        "message": f"Hello, {users[username]["name"]}!\nYou balance is {user["balance"]} ruble"
    }), media_type="application/json")
    username_signed = f"{base64.b64encode(username.encode()).decode()}.{sign_data(username)}"
    response.set_cookie(key="username", value=username_signed)
    return response
