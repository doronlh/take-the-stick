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
    generate_github_app_installation_token,
    verify_github_webhook_payload,
)

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/github-event-handler')
def github_event_handler():
    # check the API request has been signed correctly
    if not verify_github_webhook_payload(
        os.environ['GITHUB_WEBHOOK_SECRET'],
        request.headers['X-Hub-Signature'].split('=')[1],
        request.data,
    ):
        abort(400)

    github_app_token = generate_github_app_token(
        int(os.environ['GITHUB_APP_IDENTIFIER']),
        os.environ['GITHUB_PRIVATE_KEY'].encode(),
    )

    installation_id = request.json()['installation']['id']
    github_app_installation_token = generate_github_app_installation_token(github_app_token, installation_id)


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon',
    )


if __name__ == '__main__':
    app.run()
