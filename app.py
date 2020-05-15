import os
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

from utils.api import v3_get, v4_request, cache_v4_schema
from utils.auth import (
    generate_github_app_token,
    generate_secure_random_string,
    get_github_app_installation_token,
    verify_github_webhook_payload,
    get_access_token,
)
from utils.logging import configure as configure_logging


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['FLASK_SECRET_KEY']
configure_logging(app)
cache_v4_schema()


@app.before_request
def make_session_permanent():
    session.permanent = True


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

    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('signin'))

    try:
        installations = v3_get('/user/installations', access_token)['installations']
    except KeyError:
        installations = None

    if installations and len(installations) == 1:
        return redirect(url_for('repositories', installation_id=installations[0]['id']))

    return render_template('index.html', installations=installations)


@app.route('/repositories/<int:installation_id>')
def repositories(installation_id):
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


    app_identifier = int(os.environ['GITHUB_APP_IDENTIFIER'])
    private_key = os.environ['GITHUB_PRIVATE_KEY'].encode()

    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('signin'))

    github_app_token = generate_github_app_token(app_identifier, private_key)
    github_app_installation_token = get_github_app_installation_token(github_app_token, installation_id)
    installation = v3_get(f'/app/installations/{installation_id}', github_app_token)

    try:
        repositories_ = v3_get(f'/user/installations/{installation_id}/repositories', access_token)['repositories']
    except KeyError:
        repositories_ = None

    repositories_ = [v4_request(f'''
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
            }}
        }}
    ''', github_app_installation_token)['repository'] for repository in repositories_]
    return render_template('repositories.html', installation=installation, repositories=repositories_)


@app.route('/take-the-stick/<int:installation_id>', methods=['POST'])
def take_the_stick(installation_id):
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


    app_identifier = int(os.environ['GITHUB_APP_IDENTIFIER'])
    private_key = os.environ['GITHUB_PRIVATE_KEY'].encode()

    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('signin'))

    github_app_token = generate_github_app_token(app_identifier, private_key)
    github_app_installation_token = get_github_app_installation_token(github_app_token, installation_id)

    try:
        repositories_ = v3_get(f'/user/installations/{installation_id}/repositories', access_token)['repositories']
    except KeyError:
        repositories_ = None

    user_id = v4_request('query { viewer { id }}', access_token)['viewer']['id']
    for repository in repositories_:

        branch_protection_rule_id = v4_request(f'''
            query {{
                repository(name: "{repository['name']}", owner: "{repository['owner']['login']}") {{
                    branchProtectionRules(first: 1) {{
                        nodes {{
                            id
                        }}
                    }}
                }}
            }}
        ''', github_app_installation_token)['repository']['branchProtectionRules']['nodes'][0]['id']

        if request.form['action'] == 'take-the-stick':
            push_actor_ids = f'"{user_id}"'
            restrict_pushes = 'true'
        else:
            push_actor_ids = ''
            restrict_pushes = 'false'

        branch_protection_rule = v4_request(f'''
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
        ''', github_app_installation_token)['updateBranchProtectionRule']['branchProtectionRule']

    return redirect(url_for('repositories', installation_id=installation_id))


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
