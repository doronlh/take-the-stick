from contextvars import ContextVar
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from utils.github.app import GitHubApp, SessionStore


_request_ctx_var = ContextVar('request')


def _request():
    return _request_ctx_var.get()


class StarletteSessionStore(SessionStore):

    _ACCESS_TOKEN_SESSION_NAME = 'access_token'
    _ACCESS_TOKEN_EXPIRY_SESSION_NAME = 'access_token_expiry'
    _REFRESH_TOKEN_SESSION_NAME = 'refresh_token'
    _REFRESH_TOKEN_EXPIRY_SESSION_NAME = 'refresh_token_expiry'
    _STATE_SESSION_NAME = 'state'

    # access_token
    ##############

    @property
    def access_token(self):
        return _request().session.get(self._ACCESS_TOKEN_SESSION_NAME)

    @access_token.setter
    def access_token(self, val):
        _request().session[self._ACCESS_TOKEN_SESSION_NAME] = val

    # access_token_expiry
    #####################

    @property
    def access_token_expiry(self):
        return _request().session.get(self._ACCESS_TOKEN_EXPIRY_SESSION_NAME)

    @access_token_expiry.setter
    def access_token_expiry(self, val):
        _request().session[self._ACCESS_TOKEN_EXPIRY_SESSION_NAME] = val

    # refresh_token
    ###############

    @property
    def refresh_token(self):
        return _request().session.get(self._REFRESH_TOKEN_SESSION_NAME)

    @refresh_token.setter
    def refresh_token(self, val):
        _request().session[self._REFRESH_TOKEN_SESSION_NAME] = val

    # refresh_token_expiry
    ######################

    @property
    def refresh_token_expiry(self):
        return _request().session.get(self._REFRESH_TOKEN_EXPIRY_SESSION_NAME)

    @refresh_token_expiry.setter
    def refresh_token_expiry(self, val):
        _request().session[self._REFRESH_TOKEN_EXPIRY_SESSION_NAME] = val

    # state
    #######

    @property
    def state(self):
        return _request().session.get(self._STATE_SESSION_NAME)

    @state.setter
    def state(self, val):
        _request().session[self._STATE_SESSION_NAME] = val

    # sent state
    ############

    @property
    def sent_state(self):
        return _request().query_params.get('state')

    # code
    ######

    @property
    def code(self):
        return _request().query_params.get('code')

    # event signature
    ###########

    @property
    def event_signature(self):
        _, _, signature = _request().headers['X-Hub-Signature'].partition('=')
        return signature

    # event name
    ############

    @property
    def event_name(self):
        return _request().headers['X-Github-Event']

    # event delivery id
    #############

    @property
    def event_delivery_id(self):
        return _request().headers['X-Github-Delivery']

    # event payload
    ###############

    @property
    async def event_payload(self):
        body = await _request().body()
        return body


class StarletteGitHubApp:
    def __init__(self, config, signin_redirect_endpoint):
        self._github_app = GitHubApp(
            client_id=config('GITHUB_APP_CLIENT_ID'),
            client_secret=config('GITHUB_APP_CLIENT_SECRET'),
            identifier=config('GITHUB_APP_IDENTIFIER', cast=int),
            private_key_path=config('GITHUB_PRIVATE_KEY_PATH'),
            webhook_secret=config('GITHUB_WEBHOOK_SECRET'),
            session_store=StarletteSessionStore(),
            signin_redirect_uri=signin_redirect_endpoint,
            process_signin_redirect_uri=self._process_signin_redirect_uri
        )

    @staticmethod
    def _process_signin_redirect_uri(signin_redirect_uri):
        return _request().url_for(signin_redirect_uri)

    def __getattr__(self, name):
        return getattr(self._github_app, name)


# https://github.com/encode/starlette/issues/420#issue-417901877
class RequestContextMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        context_var_token = _request_ctx_var.set(request)
        response = await call_next(request)
        _request_ctx_var.reset(context_var_token)
        return response
