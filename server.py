from typing import Optional

import hmac
import hashlib
import base64

import json

from fastapi import FastAPI, Cookie, Form, Body
from fastapi import responses
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = 'a2dddab7e603531b6cf7ffaa4b5013b0836f9087bb11664df9afe3e145392c32'
PASSWORD_SALT = '74fe9eecf40743eabb3a3566498485ce121097244f775544930872f3b6390eea'

users = {'alexey@user.com': {
    'name': 'Алексей', 
    'password': 'df0c54b681d5f589ac37bb282c57bb2d51747f12d9f00f6fd1c4aaaed70b75b3',
    'balance': 100000
},
    'petr@user.com': {
    'name': 'Петр', 
    'password': '3cf0dd0f6f74855ee3ef6911ab62fbccb68f46c695a7a52817ba4698b241d52b',
    'balance': 555555
}
}

def verify_password(username: str, password: str) -> bool:
    password_hash =  hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower() 
    stored_password_hash = users[username]['password'].lower()
    return password_hash == stored_password_hash

def sign_data(data: str) -> str:
    '''Возвращает подписанные данные data'''
    return hmac.new(SECRET_KEY.encode(), 
        msg=data.encode(), 
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username
    
@app.get('/')
def index_page(username: Optional[str]=Cookie(default=None)):
    with open('templates/login_page.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_signed_string(username)
    if username is None:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response

    try:
        user = users[valid_username]["name"]
    except KeyError:
        response =  Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    print(user)
    return Response(f"Привет {user}!, Ваш баланс {users[valid_username]['balance']}", media_type='text/html')

@app.post('/login')
def process_login_page(data: dict = Body(...)):
    username = data['username']
    password = data['password']
    user = users.get(username)
    if not user:
        return Response(
            json.dumps({'success': False,
                        'message': 'Вы не зарегистрированы в системе'}), 
            media_type='application/json')
    if  not verify_password(username, password):
            return Response(
            json.dumps({'success': False,
                        'message': 'Неправильный пароль!'}), 
            media_type='application/json')

    response = Response(
        json.dumps({'success': True,
                    'message': f"Привет {user['name']}!, Ваш баланс {user['balance']}"}), 
        media_type='application/json')
    username_signed = f'{base64.b64encode(username.encode()).decode()}.{sign_data(username)}'
    response.set_cookie(key='username', value=username_signed)
    return response


print(verify_password('alexey@user.com', 'hard_password_404'))