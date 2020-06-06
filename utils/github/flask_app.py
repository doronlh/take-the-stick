import os
from flask import request, session, url_for
from utils.github.app import GitHubApp, SessionStore


class FlaskSessionStore(SessionStore):

    _ACCESS_TOKEN_SESSION_NAME = 'access_token'
    _ACCESS_TOKEN_EXPIRY_SESSION_NAME = 'access_token_expiry'
    _REFRESH_TOKEN_SESSION_NAME = 'refresh_token'
    _REFRESH_TOKEN_EXPIRY_SESSION_NAME = 'refresh_token_expiry'
    _STATE_SESSION_NAME = 'state'

    # access_token
    ##############

    @property
    def access_token(self):
        return session.get(self._ACCESS_TOKEN_SESSION_NAME)

    @access_token.setter
    def access_token(self, val):
        session[self._ACCESS_TOKEN_SESSION_NAME] = val

    # access_token_expiry
    #####################

    @property
    def access_token_expiry(self):
        return session.get(self._ACCESS_TOKEN_EXPIRY_SESSION_NAME)

    @access_token_expiry.setter
    def access_token_expiry(self, val):
        session[self._ACCESS_TOKEN_EXPIRY_SESSION_NAME] = val

    # refresh_token
    ###############

    @property
    def refresh_token(self):
        return session.get(self._REFRESH_TOKEN_SESSION_NAME)

    @refresh_token.setter
    def refresh_token(self, val):
        session[self._REFRESH_TOKEN_SESSION_NAME] = val

    # refresh_token_expiry
    ######################

    @property
    def refresh_token_expiry(self):
        return session.get(self._REFRESH_TOKEN_EXPIRY_SESSION_NAME)

    @refresh_token_expiry.setter
    def refresh_token_expiry(self, val):
        session[self._REFRESH_TOKEN_EXPIRY_SESSION_NAME] = val

    # state
    #######

    @property
    def state(self):
        return session.get(self._STATE_SESSION_NAME)

    @state.setter
    def state(self, val):
        session[self._STATE_SESSION_NAME] = val

    # sent state
    ############

    @property
    def sent_state(self):
        return request.args.get('state')

    # code
    ######

    @property
    def code(self):
        return request.args.get('code')

    # event signature
    ###########

    @property
    def event_signature(self):
        _, _, signature = request.headers['X-Hub-Signature'].partition('=')
        return signature

    # event name
    ############

    @property
    def event_name(self):
        return request.headers['X-Github-Event']

    # event delivery id
    #############

    @property
    def event_delivery_id(self):
        return request.headers['X-Github-Delivery']

    # event payload
    ###############

    @property
    def event_payload(self):
        return request.data


class FlaskGitHubApp:
    def __init__(self):
        self._github_app = None

    def init_app(self, signin_redirect_endpoint):
        self._github_app = GitHubApp(
            client_id=os.environ['GITHUB_APP_CLIENT_ID'],
            client_secret=os.environ['GITHUB_APP_CLIENT_SECRET'],
            identifier=int(os.environ['GITHUB_APP_IDENTIFIER']),
            private_key=os.environ['GITHUB_PRIVATE_KEY'].encode(),
            webhook_secret=os.environ['GITHUB_WEBHOOK_SECRET'],
            session_store=FlaskSessionStore(),
            signin_redirect_uri=signin_redirect_endpoint,
            process_signin_redirect_uri=self._process_signin_redirect_uri
        )

    @staticmethod
    def _process_signin_redirect_uri(signin_redirect_uri):
        return url_for(signin_redirect_uri)

    def __getattr__(self, name):
        return getattr(self._github_app, name)
