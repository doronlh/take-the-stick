import os
import re
from collections import defaultdict

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

from utils.github.app import SignInNeededException, BadEventSignatureException
from utils.github.flask_app import FlaskGitHubApp
from utils.github_requests import GitHubRequests
from utils.logging import configure as configure_logging


app = Flask(__name__)
github_app = FlaskGitHubApp()
github_app.init_app('signin')
github_requests = GitHubRequests(github_app)
app.config['SECRET_KEY'] = os.environ['FLASK_SECRET_KEY']
configure_logging(app)


@app.before_request
def make_session_permanent():
    session.permanent = True


@app.route('/')
def index():
    try:
        installations = github_requests.get_installations_for_user()
    except KeyError:
        installations = None
    except SignInNeededException:
        return redirect(url_for('signin'))

    if installations and len(installations) == 1:
        return redirect(url_for('repositories', installation_id=installations[0]['id']))

    return render_template('index.html', installations=installations)


@app.route('/repositories/<int:installation_id>')
def repositories(installation_id):

    installation = github_requests.get_installation(installation_id)
    repositories_ = github_requests.get_repositories(installation_id)
    repository_names = [repository['nameWithOwner'] for repository in repositories_]
    grouped_pull_requests = defaultdict(lambda: dict.fromkeys(repository_names, None))
    for repository in repositories_:
        for pull_request in repository['pullRequests']['nodes']:
            jira_key = re.search(r'(?:\s|^)([A-Z]+-[0-9]+)(?=\s|$|:)', pull_request['title'])
            if jira_key:
                grouped_pull_requests[jira_key[0]][repository['nameWithOwner']] = pull_request

    return render_template(
        'repositories.html',
        installation=installation,
        repositories=repositories_,
        grouped_pull_requests=grouped_pull_requests
    )


@app.route('/take-the-stick/<int:installation_id>', methods=['POST'])
def take_the_stick(installation_id):

    for repository in github_requests.get_repositories(installation_id):

        github_requests.set_branch_protection(
            installation_id=installation_id,
            repository_name=repository['name'],
            respository_owner=repository['owner']['login'],
            user_id=github_requests.get_current_user_id() if request.form['action'] == 'take-the-stick' else None
        )

    return redirect(url_for('repositories', installation_id=installation_id))


@app.route('/merge/<int:installation_id>/<jira_key>', methods=['GET'])
def merge(installation_id, jira_key):
    # file_contents = github_requests.get_file_contents(
    #     installation_id=installation_id,
    #     repository_name='Athena',
    #     repository_owner='CyberJackGit',
    #     branch='master',
    #     path='requirements.txt'
    # )
    pass


@app.route('/signin')
def signin():
    try:
        github_app.raise_if_user_not_signed_in()
        return redirect(url_for('index'))
    except SignInNeededException as sine:
        return render_template('signin.html', signin_url=sine.signin_url)


@app.route('/signout')
def signout():
    github_app.signout()
    return redirect(url_for('index'))


@app.route('/github-event-handler', methods=['POST'])
def github_event_handler():
    try:
        event_data = github_app.handle_event()
    except BadEventSignatureException:
        return abort(400)

    return {'success': True}


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon',
    )


if __name__ == '__main__':
    app.run()
