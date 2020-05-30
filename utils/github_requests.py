class GitHubRequests:
    def __init__(self, github_app):
        self._github_app = github_app

    def get_installations_for_user(self):
        return self._github_app.v3_user_get('/user/installations')['installations']

    def get_installation(self, installation_id):
        return self._github_app.v3_app_get(f'/app/installations/{installation_id}')

    def get_repositories(self, installation_id):
        try:
            repositories = (
                self._github_app.v3_user_get(f'/user/installations/{installation_id}/repositories')['repositories']
            )
        except KeyError:
            return None

        return [self._github_app.v4_installation_request(f'''
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
        ''', installation_id=installation_id)['repository'] for repository in repositories]

    def get_current_user_id(self):
        return self._github_app.v4_user_request('query { viewer { id }}')['viewer']['id']

    def set_branch_protection(self, installation_id, repository_name, respository_owner, user_id):
        branch_protection_rule_id = self._github_app.v4_installation_request(f'''
            query {{
                repository(name: "{repository_name}", owner: "{respository_owner}") {{
                    branchProtectionRules(first: 1) {{
                        nodes {{
                            id
                        }}
                    }}
                }}
            }}
        ''', installation_id=installation_id)['repository']['branchProtectionRules']['nodes'][0]['id']

        if user_id:
            push_actor_ids = f'"{user_id}"'
            restrict_pushes = 'true'
        else:
            push_actor_ids = ''
            restrict_pushes = 'false'

        self._github_app.v4_installation_request(f'''
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
