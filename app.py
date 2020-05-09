import json
import os
from flask import (
    abort,
    Flask,
    render_template,
    request,
    send_from_directory,
)
from utils.auth import (
    generate_github_app_token,
    get_github_app_installation_token,
    verify_github_webhook_payload,
)
from utils.logging import configure as configure_logging


app = Flask(__name__)
configure_logging(app)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/github-event-handler', methods=['POST'])
def github_event_handler():
    secret = os.environ['GITHUB_WEBHOOK_SECRET']
    app_identifier = int(os.environ['GITHUB_APP_IDENTIFIER'])
    private_key = os.environ['GITHUB_PRIVATE_KEY'].encode()
    _, _, signature = request.headers['X-Hub-Signature'].partition('=')
    event = request.headers['X-Github-Event']

    # check the API request has been signed correctly
    if not verify_github_webhook_payload(secret, signature, request.data):
        abort(400)

    github_app_token = generate_github_app_token(app_identifier, private_key)
    installation_id = request.json['installation']['id']
    github_app_installation_token = get_github_app_installation_token(github_app_token, installation_id)
    app.logger.info(github_app_installation_token)
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
