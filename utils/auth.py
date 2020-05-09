import hmac
import requests
import time
from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK


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
    response = requests.post(
        f'https://api.github.com/app/installations/{installation_id}/access_tokens',
        headers={
            'Authorization': f'Bearer {github_app_token}',
            'Accept': 'application/vnd.github.machine-man-preview+json',
        }
    ).json()
    try:
        return response['token']
    except KeyError:
        return None
