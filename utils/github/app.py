import calendar
import hmac
import json
from abc import ABC, abstractmethod
from aiographql.client import GraphQLClient, GraphQLRequest
from aiohttp import ClientSession
from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from functools import partialmethod
from graphql import build_client_schema
from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK
from os import urandom
from urllib.parse import quote as urlencode


class SessionStore(ABC):

    # access_token
    ##############

    @property
    @abstractmethod
    def access_token(self):
        pass

    @access_token.setter
    @abstractmethod
    def access_token(self, val):
        pass

    # access_token_expiry
    #####################

    @property
    @abstractmethod
    def access_token_expiry(self):
        pass

    @access_token_expiry.setter
    @abstractmethod
    def access_token_expiry(self, val):
        pass

    # refresh_token
    ###############

    @property
    @abstractmethod
    def refresh_token(self):
        pass

    @refresh_token.setter
    @abstractmethod
    def refresh_token(self, val):
        pass

    # refresh_token_expiry
    ######################

    @property
    @abstractmethod
    def refresh_token_expiry(self):
        pass

    @refresh_token_expiry.setter
    @abstractmethod
    def refresh_token_expiry(self, val):
        pass

    # state
    #######

    @property
    @abstractmethod
    def state(self):
        pass

    @state.setter
    @abstractmethod
    def state(self, val):
        pass

    # sent state
    ############

    @property
    @abstractmethod
    def sent_state(self):
        pass

    # code
    ######

    @property
    @abstractmethod
    def code(self):
        pass

    # event signature
    #################

    @property
    @abstractmethod
    def event_signature(self):
        pass

    # event name
    ############

    @property
    @abstractmethod
    def event_name(self):
        pass

    # event delivery id
    ###################

    @property
    @abstractmethod
    def event_delivery_id(self):
        pass

    # event payload
    ###############

    @property
    @abstractmethod
    async def event_payload(self):
        pass


@dataclass
class EventData:
    name: str
    delivery_id: str
    installation_id: str
    payload: dict


class SignInNeededException(Exception):

    _GITHUB_SIGNIN_URL_FORMAT = ('https://github.com/login/oauth/authorize?'
                                 'client_id={client_id}&redirect_uri={redirect_uri}&state={state}')

    def __init__(self, client_id, redirect_uri, state):
        super().__init__(self)
        self.signin_url = self._GITHUB_SIGNIN_URL_FORMAT.format(
            client_id=client_id,
            redirect_uri=urlencode(redirect_uri),
            state=urlencode(state)
        )


class BadEventSignatureException(Exception):
    pass


class TokenType(Enum):
    APP = auto()
    INSTALLATION = auto()
    ACCESS = auto()


_V4_SCHEMA = None


def _cache_v4_schema():
    global _V4_SCHEMA

    if _V4_SCHEMA:
        return

    with open('github_v4_schema.graphql') as source:
        introspection = json.loads(source.read())

    _V4_SCHEMA = build_client_schema(introspection)


class GitHubApp:

    _REFRESH_BUFFER = 30
    _ISO_8601_FORMAT = '%Y-%m-%dT%H:%M:%S%z'
    _GITHUB_ACCESS_TOKEN_URL = 'https://github.com/login/oauth/access_token'
    _GITHUB_ACCESS_TOKEN_HEADERS = {
        'Accept': 'application/json'
    }

    def __init__(self, client_id, client_secret, identifier, private_key_path, webhook_secret, session_store,
                 signin_redirect_uri, process_signin_redirect_uri=None):
        self._client_id = client_id
        self._client_secret = client_secret
        self._identifier = identifier
        self._private_key = self._read_private_key(private_key_path)
        self._webhook_secret = webhook_secret
        self._session_store = session_store
        self._signin_redirect_uri = signin_redirect_uri
        self._process_signin_redirect_uri = process_signin_redirect_uri or (
            lambda signin_redirect_uri_: signin_redirect_uri_)
        self._current_app_token = None
        self._current_app_token_expiry = None
        self._current_installation_tokens = {}
        self._current_installation_token_expiries = {}
        self._client_session = None

        _cache_v4_schema()

    async def _get_client_session(self):
        if self._client_session is None:
            self._client_session = ClientSession()
        return self._client_session

    async def close(self):
        if self._client_session:
            await self._client_session.close()

    @staticmethod
    def _read_private_key(private_key_path):
        with open(private_key_path, 'rb') as file:
            private_key = file.read()
        return private_key

    @staticmethod
    def _convert_datetime_to_timestamp(dt):
        # is int(time.time()) good enough? It seems to produce the same results
        return calendar.timegm(dt.utctimetuple())

    @classmethod
    def _get_now_timestamp(cls):
        return cls._convert_datetime_to_timestamp(datetime.utcnow())

    @classmethod
    def _iso8601_to_timestamp(cls, iso8601_str):
        return cls._convert_datetime_to_timestamp(datetime.strptime(iso8601_str, cls._ISO_8601_FORMAT))

    @classmethod
    def _is_token_expired(cls, expiry_timestamp):
        return expiry_timestamp is None or expiry_timestamp - cls._get_now_timestamp() < cls._REFRESH_BUFFER

    @staticmethod
    def _generate_secure_random_string():
        random_bytes = urandom(64)
        return b64encode(random_bytes).decode('utf-8')

    def _get_app_token(self):

        expired = self._is_token_expired(self._current_app_token_expiry)
        if expired:
            now = self._get_now_timestamp()
            expiry = now + (10 * 60)
            self._current_app_token_expiry = expiry
            token = JWT(
                header={'alg': 'RS256'},
                claims={
                    'iat': now,
                    'exp': expiry,
                    'iss': self._identifier,
                },
                algs=['RS256'],
            )

            token.make_signed_token(JWK.from_pem(self._private_key))
            self._current_app_token = token.serialize()
        return self._current_app_token

    async def _get_installation_token(self, installation_id):

        expired = self._is_token_expired(self._current_installation_token_expiries.get(installation_id))
        if expired:
            response = await self.v3_app_post(f'/app/installations/{installation_id}/access_tokens')
            try:
                # get the values from the response dict before assigning to self._current_installation_tokenxxx
                # since we want to make sure both keys exist. If one doesn't exist then the KeyError will be raised
                # without modifying either _current_installation_tokens or _current_installation_token_expiries
                token = response['token']
                expires_at = self._iso8601_to_timestamp(response['expires_at'])
                self._current_installation_tokens[installation_id] = token
                self._current_installation_token_expiries[installation_id] = expires_at
            except KeyError:
                return None
        return self._current_installation_tokens[installation_id]

    async def _get_access_token(self, code=None, sent_state=None):
        current_access_token = self._session_store.access_token
        access_token_expired = self._is_token_expired(self._session_store.access_token_expiry)
        current_refresh_token = self._session_store.refresh_token
        refresh_token_expired = self._is_token_expired(self._session_store.refresh_token_expiry)
        expected_state = self._session_store.state

        if current_access_token and not access_token_expired:
            return current_access_token
        elif current_refresh_token and not refresh_token_expired:
            request_params = {
                'refresh_token': current_refresh_token,
                'grant_type': 'refresh_token',
                'client_id': self._client_id,
                'client_secret': self._client_secret,
            }
        elif code and sent_state and expected_state and sent_state == expected_state:
            request_params = {
                'client_id': self._client_id,
                'client_secret': self._client_secret,
                'code': code,
            }
        else:
            raise self._signin_needed_exception()

        now_timestamp = self._get_now_timestamp()

        request_kwargs = {
            'url': self._GITHUB_ACCESS_TOKEN_URL,
            'params': request_params,
            'headers': self._GITHUB_ACCESS_TOKEN_HEADERS,
        }
        async with (await self._get_client_session()).post(**request_kwargs) as response:
            response = await response.json()

        try:
            current_access_token = response['access_token']
            expires_in = response['expires_in']
            current_refresh_token = response['refresh_token']
            refresh_token_expires_in = response['refresh_token_expires_in']

            self._session_store.access_token = current_access_token
            self._session_store.access_token_expiry = now_timestamp + expires_in
            self._session_store.refresh_token = current_refresh_token
            self._session_store.refresh_token_expiry = now_timestamp + refresh_token_expires_in

            return current_access_token
        except KeyError:
            raise self._signin_needed_exception()

    def _signin_needed_exception(self):
        state = self._generate_secure_random_string()
        self._session_store.state = state
        return SignInNeededException(
            client_id=self._client_id,
            redirect_uri=self._process_signin_redirect_uri(self._signin_redirect_uri),
            state=state
        )

    async def _get_token_for_request(self, token_type, installation_id=None):
        if token_type == TokenType.APP:
            return self._get_app_token()
        elif token_type == TokenType.INSTALLATION:
            return await self._get_installation_token(installation_id)
        elif token_type == TokenType.ACCESS:
            return await self._get_access_token(
                code=self._session_store.code, sent_state=self._session_store.sent_state)
        else:
            raise ValueError()

    async def _is_event_signature_valid(self):
        msg = await self._session_store.event_payload
        mac = hmac.new(self._webhook_secret.encode(), msg=msg, digestmod='sha1')
        return hmac.compare_digest(mac.hexdigest(), self._session_store.event_signature)

    async def v3_request(self, session_method_name, token_type, url, data=None, installation_id=None):
        client_session = await self._get_client_session()
        session_method = getattr(client_session, session_method_name)
        kwargs = {
            'url': f'https://api.github.com{url}',
            'data': data,
            'headers': {
                'Authorization': f'Bearer {await self._get_token_for_request(token_type, installation_id)}',
                'Accept': 'application/vnd.github.machine-man-preview+json',
            }
        }

        async with session_method(**kwargs) as response:
            return await response.json()

    v3_app_get = partialmethod(v3_request, 'get', TokenType.APP)
    v3_app_post = partialmethod(v3_request, 'post', TokenType.APP)
    v3_installation_get = partialmethod(v3_request, 'get', TokenType.INSTALLATION)
    v3_installation_post = partialmethod(v3_request, 'post', TokenType.INSTALLATION)
    v3_user_get = partialmethod(v3_request, 'get', TokenType.ACCESS)
    v3_user_post = partialmethod(v3_request, 'post', TokenType.ACCESS)

    async def v4_request(self, token_type, request_string, installation_id=None):

        client = GraphQLClient(
            endpoint='https://api.github.com/graphql',
            headers={
                'Authorization': f'Bearer {await self._get_token_for_request(token_type, installation_id)}'
            },
            schema=_V4_SCHEMA,
        )
        request = GraphQLRequest(query=request_string)
        return (await client.query(request=request)).data

    v4_app_request = partialmethod(v4_request, TokenType.APP)
    v4_installation_request = partialmethod(v4_request, TokenType.INSTALLATION)
    v4_user_request = partialmethod(v4_request, TokenType.ACCESS)

    async def raise_if_user_not_signed_in(self):
        await self._get_token_for_request(TokenType.ACCESS)

    def signout(self):
        self._session_store.access_token = None
        self._session_store.access_token_expiry = None
        self._session_store.refresh_token = None
        self._session_store.refresh_token_expiry = None

    async def handle_event(self):
        event_signature_valid = await self._is_event_signature_valid()

        if event_signature_valid:
            event_payload = await self._session_store.event_payload
            event_payload = json.loads(event_payload.decode())
            return EventData(
                name=self._session_store.event_name,
                delivery_id=self._session_store.event_delivery_id,
                installation_id=event_payload['installation']['id'],
                payload=event_payload,
            )
        else:
            raise BadEventSignatureException()
