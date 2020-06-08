class GitHubRequests:
    def __init__(self, github_app):
        self._github_app = github_app

    async def get_installations_for_user(self):
        return (await self._github_app.v3_user_get('/user/installations'))['installations']

    async def get_installation(self, installation_id):
        return await self._github_app.v3_app_get(f'/app/installations/{installation_id}')

    async def get_repositories(self, installation_id):
        try:
            repositories = (
                (await self._github_app.v3_user_get(f'/user/installations/{installation_id}/repositories'))[
                    'repositories']
            )
        except KeyError:
            return None

        return [(await self._github_app.v4_installation_request(f'''
            query {{
                repository(name: "{repository['name']}", owner: "{repository['owner']['login']}") {{
                    nameWithOwner
                    name
                    url
                    owner {{
                        login
                    }}
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
        ''', installation_id=installation_id))['repository'] for repository in repositories]

    async def get_current_user_id(self):
        return (await self._github_app.v4_user_request('query { viewer { id }}'))['viewer']['id']

    async def set_branch_protection(self, installation_id, repository_name, respository_owner, user_id):
        branch_protection_rule_id = (await self._github_app.v4_installation_request(f'''
            query {{
                repository(name: "{repository_name}", owner: "{respository_owner}") {{
                    branchProtectionRules(first: 1) {{
                        nodes {{
                            id
                        }}
                    }}
                }}
            }}
        ''', installation_id=installation_id))['repository']['branchProtectionRules']['nodes'][0]['id']

        if user_id:
            push_actor_ids = f'"{user_id}"'
            restrict_pushes = 'true'
        else:
            push_actor_ids = ''
            restrict_pushes = 'false'

        await self._github_app.v4_installation_request(f'''
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

    async def get_file_contents(self, installation_id, repository_name, repository_owner, branch, path):
        return await self._github_app.v4_installation_request(f'''
            query {{
                repository(name: "{repository_name}", owner: "{repository_owner}") {{
                    object(expression: "{branch}:{path}") {{
                        ... on Blob {{
                            text
                        }}
                    }}
                }}
            }}
        ''', installation_id=installation_id)
