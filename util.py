import json
import logging
import time
import urllib, string
import sqlite3
from contextlib import closing
from functools import wraps

from werkzeug.exceptions import Forbidden, Unauthorized
import requests

from flask import Response, session, request
from jwcrypto import jwt, jwk, jws

OKTA_BASE_URL='https://dev-41962235.okta.com'
OKTA_CLIENT_ID='0oa9ryjpbeTkZMSHF5d7'
OKTA_CLIENT_SECRET='e2MGsVMNbJkXZkbIUNWEe5qA0BZ9IAXKP4FLb4Ae'
OKTA_ISSUER='https://dev-41962235.okta.com/oauth2/default'
OKTA_AUDIENCE='api://default'

FAKE_TOKEN_EXCHANGE_BEARER='af686e0c'

JWK_CACHE = []


def get_token_from_header():
    auth_header = request.headers.get('Authorization')
    type_, token = auth_header.split(' ')
    return token


def _strip_email(email):
    # NOTE: FAULTY STRING STRIPPER FOR DEMONSTRATION PURPOSES
    return urllib.parse.unquote(email).translate({ord(c): None for c in string.whitespace})


# TODO: this should probably be a class that can take auth server params as config
def validate_access_token(token, scopes, user_id=None):
    global JWK_CACHE
    if len(JWK_CACHE) == 0:
        url = '{}/v1/keys'.format(OKTA_ISSUER)
        resp = requests.get(url)
        keys = json.loads(resp.content)['keys']
    else:
        keys = JWK_CACHE
    # verify token
    # TODO: use keyset 'add' since there could be multiple keys: jwk.JWKSet() (instead of using loop)
    for k in keys:
        try:
            key = jwk.JWK(**k)
            # NOTE: .verify() is implied by checking the claims with the key
            verified_token = jwt.JWT(key=key, jwt=token)
            break
        except jws.InvalidJWSSignature:
            # TODO: warning?
            pass
        except jwt.JWTExpired:
            raise Unauthorized

    # check claims
    claims = json.loads(verified_token.claims)
    if user_id:

        # ensure user_id matches uid in access token
        # assert claims['uid'] == user_id
        
        # alternatively use email address/username
        
        # NOTE: using faulty string stripper for demo purposes
        if claims['sub'] != user_id:
            assert _strip_email(claims['sub']) == _strip_email(user_id) or claims['uid'] == user_id

    # TODO: raise custom error to indicate scopes didn't match, other failures
    for scope in scopes:
        assert scope in claims['scp']

    assert claims['iss'] == OKTA_ISSUER
    assert claims['aud'] == OKTA_AUDIENCE
    return claims


def authorize(scopes=[], user_id=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                token = get_token_from_header()
                claims = validate_access_token(token, scopes, user_id)
            except Exception as e:
                logging.exception(str(e))
                raise Unauthorized
            kwargs.update({'claims': claims})
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def check_auth_user(username, password):
    with closing(sqlite3.connect(':memory:')) as connection:
        with closing(connection.cursor()) as cursor:
            try:
                cursor.execute('CREATE TABLE users (user_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, password TEXT)')
            except sqlite3.OperationalError:
                pass
            cursor.execute("INSERT INTO users (name,password) VALUES ('admin', 's3cr3t')")
            cursor.execute("INSERT INTO users (name,password) VALUES ('user1', 'p@ssw0rd')")
            connection.commit()
            rows = cursor.execute("SELECT name, password FROM users WHERE name='" + username + "' AND password='" + password +"'").fetchall()
            return rows


def exchange_token(payload):
    # backdoor/flaw is here in this conditional
    # real system might at least get VIN from DB to confirm it exists
    if not payload['customerId'][:4] == 'vin:':
        try:
            validate_access_token(get_token_from_header(), scopes=[], user_id=payload['customerId'])
        except:
            raise Unauthorized
    return FAKE_TOKEN_EXCHANGE_BEARER


def authorize_exch():
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                token = get_token_from_header()
                assert token == FAKE_TOKEN_EXCHANGE_BEARER
            except Exception as e:
                logging.exception(str(e))
                raise Unauthorized
            return f(*args, **kwargs)
        return decorated_function
    return decorator
