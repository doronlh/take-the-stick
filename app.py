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
from utils.logging import configure as configure_logging


app = Flask(__name__)
github_app = FlaskGitHubApp()
github_app.init_app('signin')
app.config['SECRET_KEY'] = os.environ['FLASK_SECRET_KEY']
configure_logging(app)


@app.before_request
def make_session_permanent():
    session.permanent = True


@app.route('/')
def index():
    try:
        installations = github_app.v3_user_get('/user/installations')['installations']
    except KeyError:
        installations = None
    except SignInNeededException:
        return redirect(url_for('signin'))

    if installations and len(installations) == 1:
        return redirect(url_for('repositories', installation_id=installations[0]['id']))

    return render_template('index.html', installations=installations)


@app.route('/repositories/<int:installation_id>')
def repositories(installation_id):
    installation = github_app.v3_app_get(f'/app/installations/{installation_id}')

    try:
        repositories_ = github_app.v3_user_get(f'/user/installations/{installation_id}/repositories')['repositories']
    except KeyError:
        repositories_ = None

    repositories_ = [github_app.v4_installation_request(f'''
        query {{
            repository(name: "{repository['name']}", owner: "{repository['owner']['login']}") {{
                nameWithOwner
                url
                branchProtectionRules(first: 1) {{
                    nodes {{
                        id
                        restrictsPushes
                        pushAllowances(first: 20) {{
                            nodes {{
                                actor {{
                                    __typename
                                    ... on User {{
                                        login
                                        name
                                    }}
                                }}
                            }}
                        }}
                    }}
                }}
                pullRequests(states: OPEN, first: 100) {{
                    nodes {{
                        title
                        url
                    }}
                }}
            }}
        }}
    ''', installation_id=installation_id)['repository'] for repository in repositories_]

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
    try:
        repositories_ = github_app.v3_user_get(f'/user/installations/{installation_id}/repositories')['repositories']
    except KeyError:
        repositories_ = None

    user_id = github_app.v4_user_request('query { viewer { id }}')['viewer']['id']
    for repository in repositories_:

        branch_protection_rule_id = github_app.v4_installation_request(f'''
            query {{
                repository(name: "{repository['name']}", owner: "{repository['owner']['login']}") {{
                    branchProtectionRules(first: 1) {{
                        nodes {{
                            id
                        }}
                    }}
                }}
            }}
        ''', installation_id=installation_id)['repository']['branchProtectionRules']['nodes'][0]['id']

        if request.form['action'] == 'take-the-stick':
            push_actor_ids = f'"{user_id}"'
            restrict_pushes = 'true'
        else:
            push_actor_ids = ''
            restrict_pushes = 'false'

        github_app.v4_installation_request(f'''
            mutation {{
                updateBranchProtectionRule(input: {{
                        branchProtectionRuleId: "{branch_protection_rule_id}",
                        pushActorIds: [{push_actor_ids}], 
                        restrictsPushes: {restrict_pushes}
                }}) {{
                    branchProtectionRule {{
                        pushAllowances(first: 1) {{
                            nodes {{
                                actor {{
                                    ... on User {{
                                        login
                                        name
                                    }}
                                }}
                            }}
                        }}
                    }}
                }}
            }}
        ''', installation_id=installation_id)

    return redirect(url_for('repositories', installation_id=installation_id))


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
