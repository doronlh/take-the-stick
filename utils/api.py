import json
import requests
from functools import partial
from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport
from graphql import  build_client_schema

_V4_SCHEMA = None


def cache_v4_schema():
    global _V4_SCHEMA

    with open('github_v4_schema.graphql') as source:
        introspection = json.loads(source.read())

    _V4_SCHEMA = build_client_schema(introspection)


def v3_request(requests_method, url, token, data=None):
    return requests_method(
        f'https://api.github.com{url}',
        data=data,
        headers={
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github.machine-man-preview+json',
        }
    ).json()


v3_get = partial(v3_request, requests.get)
v3_post = partial(v3_request, requests.post)


def v4_request(request_string, token):
    client = Client(
        transport=RequestsHTTPTransport(
            url='https://api.github.com/graphql',
            headers={'Authorization': f'bearer {token}'},
            use_json=True,
        ),
        schema=_V4_SCHEMA
    )
    return client.execute(gql(request_string))
