import re
import uvicorn
from collections import defaultdict
from starlette.applications import Starlette
from starlette.config import Config
from starlette.datastructures import Secret
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse, FileResponse, JSONResponse
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from utils.github.app import SignInNeededException, BadEventSignatureException
from utils.github.starlette_app import StarletteGitHubApp, RequestContextMiddleware
from utils.github_requests import GitHubRequests
# from utils.logging import configure as configure_logging


config = Config('.env')
SECRET_KEY = config('SECRET_KEY', cast=Secret)


middleware = [
    Middleware(SessionMiddleware, secret_key=SECRET_KEY),
    Middleware(RequestContextMiddleware),
]


github_app = StarletteGitHubApp(config, 'signin')
github_requests = GitHubRequests(github_app)


async def on_shutdown():
    await github_app.close()


app = Starlette(debug=True, middleware=middleware, on_shutdown=[on_shutdown])
templates = Jinja2Templates(directory='templates')
app.mount('/static', StaticFiles(directory='static'), name='static')
# configure_logging(app)


@app.route('/')
async def index(request):
    try:
        installations = await github_requests.get_installations_for_user()
    except KeyError:
        installations = None
    except SignInNeededException:
        return RedirectResponse(request.url_for('signin'), status_code=302)
    if installations and len(installations) == 1:
        response = RedirectResponse(
            request.url_for('repositories', installation_id=installations[0]['id']),
            status_code=302
        )
    else:
        response = templates.TemplateResponse('index.html', {
            'request': request,
            'installations': installations,
        })

    return response


@app.route('/repositories/{installation_id:int}')
async def repositories(request):
    installation_id = request.path_params['installation_id']
    installation = await github_requests.get_installation(installation_id)
    repositories_ = await github_requests.get_repositories(installation_id)
    repository_names = [repository['nameWithOwner'] for repository in repositories_]
    grouped_pull_requests = defaultdict(lambda: dict.fromkeys(repository_names, None))
    for repository in repositories_:
        for pull_request in repository['pullRequests']['nodes']:
            jira_key = re.search(r'(?:\s|^)([A-Z]+-[0-9]+)(?=\s|$|:)', pull_request['title'])
            if jira_key:
                grouped_pull_requests[jira_key[0]][repository['nameWithOwner']] = pull_request

    return templates.TemplateResponse(
        'repositories.html', {
            'request': request,
            'installation': installation,
            'repositories': repositories_,
            'grouped_pull_requests': grouped_pull_requests,
        }
    )


@app.route('/take-the-stick/{installation_id:int}', methods=['POST'])
async def take_the_stick(request):
    installation_id = request.path_params['installation_id']
    form = await request.form()
    for repository in await github_requests.get_repositories(installation_id):
        await github_requests.set_branch_protection(
            installation_id=installation_id,
            repository_name=repository['name'],
            respository_owner=repository['owner']['login'],
            user_id=(await github_requests.get_current_user_id()) if form['action'] == 'take-the-stick' else None
        )

    return RedirectResponse(request.url_for('repositories', installation_id=installation_id), status_code=302)


@app.route('/merge/{installation_id:int}/{jira_key:str}', methods=['GET'])
async def merge(request):
    installation_id = request.path_params['installation_id']
    jira_key = request.path_params['jira_key']
    # file_contents = await github_requests.get_file_contents(
    #     installation_id=installation_id,
    #     repository_name='Athena',
    #     repository_owner='CyberJackGit',
    #     branch='master',
    #     path='requirements.txt'
    # )
    pass


@app.route('/signin')
async def signin(request):
    try:
        await github_app.raise_if_user_not_signed_in()
        return RedirectResponse(request.url_for('index'), status_code=302)
    except SignInNeededException as sine:
        return templates.TemplateResponse(
            'signin.html', {
                'request': request,
                'signin_url': sine.signin_url,
            }
        )


@app.route('/signout')
async def signout(request):
    github_app.signout()
    return RedirectResponse(request.url_for('index'), status_code=302)


@app.route('/github-event-handler', methods=['POST'])
async def github_event_handler(request):
    try:
        event_data = await github_app.handle_event()
        print(event_data)
    except BadEventSignatureException:
        raise HTTPException(400)
    return JSONResponse({'success': True})


@app.route('/favicon.ico')
async def favicon(request):
    return FileResponse('static/favicon.ico')


if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8000)
