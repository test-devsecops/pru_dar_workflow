from jira_utility.jira_api_endpoints import JiraApiEndpoints
from jira_utility.jira_config_utility import Config

from utils.exception_handler import ExceptionHandler
from utils.http_utility import HttpRequests
from utils.yml_file_utility import load_map

from urllib.parse import urlencode

import requests
import base64
import sys


class JiraApiActions:

    def __init__(self, configEnvironment=None):
        self.httpRequest = HttpRequests()
        self.apiEndpoints = JiraApiEndpoints()
        self.config = Config()
        self.fields = self.get_field_mapping()

        self.token, self.project_id, self.jira_url, self.issuetype_id = self.config.get_config(configEnvironment)
        
    @ExceptionHandler.handle_exception
    def get_field_mapping(self):
        fmap = load_map("config/field_mapping.yml")
        return fmap

    @ExceptionHandler.handle_exception
    def get_queues(self):

        endpoint = self.apiEndpoints.get_queues(self.project_id)
        url = f"https://{self.jira_url}{endpoint}"

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}"
        }

        response = self.httpRequest.get_api_request(url, headers)
        return response

    @ExceptionHandler.handle_exception
    def create_issue(self, fields_values):

        endpoint = self.apiEndpoints.create_issue()
        url = f"https://{self.jira_url}{endpoint}{fields_values["issue_id"]}"

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}"
        }

        payload = {
            "fields": {
                "description": str(fields_values['description']),
                "summary": fields_values["summary"],
                self.fields["lbu"] : fields_values["lbu"],
                # self.fields["project_name"] : fields_values["project_name"],
                self.fields["application_name"] : fields_values["application_name"],
                self.fields["scan_report_link"] : fields_values["scan_report_link"],
                self.fields["num_of_critical"] : fields_values["num_of_critical"],
                self.fields["num_of_high"] : fields_values["num_of_high"],
                self.fields["num_of_medium"] : fields_values["num_of_medium"],
                self.fields["num_of_low"] : fields_values["num_of_low"],
                self.fields["scan_url"] : fields_values['scan_url'],
                self.fields["tag"] : fields_values['tag'],
            }
        }

        response = self.httpRequest.put_api_request(url, headers=headers, json=payload)
        return response