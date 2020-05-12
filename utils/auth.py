import calendar
import hmac
import requests
import time
from base64 import b64encode
from datetime import datetime
from os import urandom
from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK

from utils.api import v3_post


def generate_secure_random_string():
    random_bytes = urandom(64)
    return b64encode(random_bytes).decode('utf-8')


def verify_github_webhook_payload(github_webhook_secret, signature, payload):
    mac = hmac.new(github_webhook_secret.encode(), msg=payload, digestmod='sha1')
    return hmac.compare_digest(mac.hexdigest(), signature)


def generate_github_app_token(github_app_identifier, github_private_key):
    now = int(time.time())
    token = JWT(
        header={'alg': 'RS256'},
        claims={
            'iat': now,
            'exp': now + (10 * 60),
            'iss': github_app_identifier,
        },
        algs=['RS256'],
    )

    token.make_signed_token(JWK.from_pem(github_private_key))
    return token.serialize()


def get_github_app_installation_token(github_app_token, installation_id):
    response = v3_post(f'/app/installations/{installation_id}/access_tokens', github_app_token)
    try:
        return response['token']
    except KeyError:
        return None


def get_now_timestamp():
    return calendar.timegm(datetime.utcnow().utctimetuple())


def get_access_token(
    current_access_token,
    github_app_client_id,
    github_app_client_secret,
    access_token_expiry,
    refresh_token,
    refresh_token_expiry,
    sent_state=None,
    expected_state=None,
    code=None,
):

    timestamp = get_now_timestamp()

    refresh_buffer = 30
    access_token_expired = access_token_expiry is None or access_token_expiry - timestamp < refresh_buffer
    refresh_token_expired = refresh_token_expiry is None or refresh_token_expiry - timestamp < refresh_buffer

    if current_access_token and not access_token_expired:
        return current_access_token, access_token_expiry, refresh_token, refresh_token_expiry
    elif refresh_token and not refresh_token_expired:
        request_params = {
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token',
            'client_id': github_app_client_id,
            'client_secret': github_app_client_secret,
        }
    elif code and sent_state and expected_state and sent_state == expected_state:
        request_params = {
            'client_id': github_app_client_id,
            'client_secret': github_app_client_secret,
            'code': code,
        }
    else:
        return (None,) * 4

    response = requests.post('https://github.com/login/oauth/access_token', params=request_params, headers={
        'Accept': 'application/json'
    }).json()

    try:
        return (
            response['access_token'],
            timestamp + response['expires_in'],
            response['refresh_token'],
            timestamp + response['refresh_token_expires_in']
        )
    except KeyError:
        return (None,) * 4
