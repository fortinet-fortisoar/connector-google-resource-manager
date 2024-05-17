"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import json
from requests import request
from connectors.core.connector import get_logger, ConnectorError
from .google_api_auth import *

RESOURCE_MANAGER_API_VERSION = 'v3'

logger = get_logger('google-resource-manager')


def api_request(method, endpoint, connector_info, config, params=None, data=None, headers={}):
    try:
        go = GoogleAuth(config)
        endpoint = go.host + "/" + endpoint
        token = go.validate_token(config, connector_info)
        headers['Authorization'] = token
        headers['Content-Type'] = 'application/json'
        response = request(method, endpoint, headers=headers, params=params, data=data, verify=go.verify_ssl)
        try:
            from connectors.debug_utils.curl_script import make_curl
            make_curl(method, endpoint, headers=headers, params=params, data=data, verify_ssl=go.verify_ssl)
        except Exception as err:
            logger.error(f"Error in curl utils: {str(err)}")
        if response.ok or response.status_code == 204:
            if 'json' in str(response.headers):
                return response.json()
            else:
                return response
        else:
            logger.error("{0}".format(response.status_code))
            raise ConnectorError("{0}:{1}".format(response.status_code, response.text))
    except requests.exceptions.SSLError:
        raise ConnectorError('SSL certificate validation failed')
    except requests.exceptions.ConnectTimeout:
        raise ConnectorError('The request timed out while trying to connect to the server')
    except requests.exceptions.ReadTimeout:
        raise ConnectorError(
            'The server did not send any data in the allotted amount of time')
    except requests.exceptions.ConnectionError:
        raise ConnectorError('Invalid Credentials')
    except Exception as err:
        raise ConnectorError(str(err))


def check_payload(payload):
    result = {}
    for k, v in payload.items():
        if isinstance(v, dict):
            x = check_payload(v)
            if len(x.keys()) > 0:
                result[k] = x
        elif isinstance(v, list):
            p = []
            for c in v:
                if isinstance(c, dict):
                    x = check_payload(c)
                    if len(x.keys()) > 0:
                        p.append(x)
                elif c is not None and c != '':
                    p.append(c)
            if p != []:
                result[k] = p
        elif v is not None and v != '':
            result[k] = v
    return result


def build_payload(payload):
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    return payload


def search_organizations(config, params, connector_info):
    try:
        url = '{0}/organizations:search'.format(RESOURCE_MANAGER_API_VERSION)
        query_parameters = build_payload(params)
        response = api_request('GET', url, connector_info, config, params=query_parameters)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_organization_details(config, params, connector_info):
    try:
        url = '{0}/documents/{1}'.format(RESOURCE_MANAGER_API_VERSION, params.get('organization_name'))
        response = api_request('GET', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def create_project(config, params, connector_info):
    try:
        url = '{0}/projects'.format(RESOURCE_MANAGER_API_VERSION)
        payload = {
            "projectId": params.get('projectId'),
            "displayName": params.get('displayName'),
            "labels": params.get('labels'),
            "tags": params.get('tags')
        }
        if params.get('additional_parameters'):
            payload.update(params.get('additional_parameters'))
        payload = check_payload(payload)
        response = api_request('POST', url, connector_info, config, data=json.dumps(payload))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def search_projects(config, params, connector_info):
    try:
        url = '{0}/projects:search'.format(RESOURCE_MANAGER_API_VERSION)
        query_parameters = build_payload(params)
        response = api_request('GET', url, connector_info, config, params=query_parameters)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_project_details(config, params, connector_info):
    try:
        url = '{0}/{1}'.format(RESOURCE_MANAGER_API_VERSION, params.get('project_name'))
        response = api_request('GET', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def update_project(config, params, connector_info):
    try:
        url = '{0}/{1}'.format(RESOURCE_MANAGER_API_VERSION, params.get('project_name'))
        payload = {
            "displayName": params.get('displayName'),
            "labels": params.get('labels'),
            "tags": params.get('tags')
        }
        if params.get('additional_parameters'):
            payload.update(params.get('additional_parameters'))
        payload = check_payload(payload)
        response = api_request('PATCH', url, connector_info, config, data=json.dumps(payload))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def delete_project(config, params, connector_info):
    try:
        url = '{0}/{1}'.format(RESOURCE_MANAGER_API_VERSION, params.get('project_name'))
        response = api_request('DELETE', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def restore_project(config, params, connector_info):
    try:
        url = '{0}/{1}:undelete'.format(RESOURCE_MANAGER_API_VERSION, params.get('project_name'))
        response = api_request('POST', url, connector_info, config)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config, connector_info):
    try:
        params = {}
        return check(config, connector_info) and search_projects(config, params, connector_info)
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'search_organizations': search_organizations,
    'get_organization_details': get_organization_details,
    'create_project': create_project,
    'search_projects': search_projects,
    'get_project_details': get_project_details,
    'update_project': update_project,
    'delete_project': delete_project,
    'restore_project': restore_project
}
