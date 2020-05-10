import json
import os
import requests
from flask import (
    abort,
    Flask,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from utils.auth import (
    generate_github_app_token,
    get_github_app_installation_token,
    generate_secure_random_string,
    verify_github_webhook_payload, get_access_token,
)
from utils.logging import configure as configure_logging


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['FLASK_SECRET_KEY']
configure_logging(app)


@app.route('/')
def index():
    (session['access_token'],
     session['access_token_expiry'],
     session['refresh_token'],
     session['refresh_token_expiry']) = get_access_token(
        current_access_token=session.get('access_token'),
        github_app_client_id=os.environ['GITHUB_APP_CLIENT_ID'],
        github_app_client_secret=os.environ['GITHUB_APP_CLIENT_SECRET'],
        access_token_expiry=session.get('access_token_expiry'),
        refresh_token=session.get('refresh_token'),
        refresh_token_expiry=session.get('refresh_token_expiry'),
    )

    if session.get('access_token') is None:
        return redirect(url_for('signin'))

    return render_template('index.html', access_token=session.get('access_token'))


@app.route('/signin')
def signin():

    (session['access_token'],
     session['access_token_expiry'],
     session['refresh_token'],
     session['refresh_token_expiry']) = get_access_token(
        current_access_token=session.get('access_token'),
        github_app_client_id=os.environ['GITHUB_APP_CLIENT_ID'],
        github_app_client_secret=os.environ['GITHUB_APP_CLIENT_SECRET'],
        access_token_expiry=session.get('access_token_expiry'),
        refresh_token=session.get('refresh_token'),
        refresh_token_expiry=session.get('refresh_token_expiry'),
        sent_state=request.args.get('state'),
        expected_state=session.get('state'),
        code=request.args.get('code'),
    )

    if session['access_token']:
        return redirect(url_for('index'))
    else:
        if session.get('state') is None:
            session['state'] = generate_secure_random_string()
        return render_template(
            'signin.html',
            client_id=os.environ['GITHUB_APP_CLIENT_ID'],
            redirect_uri=url_for(request.endpoint, _external=True),
            state=session['state'],
        )


@app.route('/signout')
def signout():
    session.pop('access_token', None)
    session.pop('access_token_expiry', None)
    session.pop('refresh_token', None)
    session.pop('refresh_token_expiry', None)
    return redirect(url_for('index'))


@app.route('/github-event-handler', methods=['POST'])
def github_event_handler():
    secret = os.environ['GITHUB_WEBHOOK_SECRET']
    app_identifier = int(os.environ['GITHUB_APP_IDENTIFIER'])
    private_key = os.environ['GITHUB_PRIVATE_KEY'].encode()
    _, _, signature = request.headers['X-Hub-Signature'].partition('=')
    event = request.headers['X-Github-Event']
    delivery_id = request.headers['X-Github-Delivery']

    # check the API request has been signed correctly
    if not verify_github_webhook_payload(secret, signature, request.data):
        return abort(400)

    github_app_token = generate_github_app_token(app_identifier, private_key)
    installation_id = request.json['installation']['id']
    github_app_installation_token = get_github_app_installation_token(github_app_token, installation_id)
    app.logger.info(json.dumps(request.json, sort_keys=True, indent=4))
    return "hi"


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon',
    )


if __name__ == '__main__':
    app.run()
