
from checkmarx_utility.cx_api_endpoints import CxApiEndpoints
from checkmarx_utility.cx_config_utility import Config

from utils.exception_handler import ExceptionHandler
from utils.http_utility import HttpRequests

from urllib.parse import urlencode

import requests
import base64
import sys

class CxApiActions:

    def __init__(self, configEnvironment):
        self.httpRequest = HttpRequests()
        self.apiEndpoints = CxApiEndpoints()
        self.config = Config("config.env")

        self.token, self.tenant_name, self.tenant_iam_url, self.tenant_url = self.config.get_config(configEnvironment)

    @ExceptionHandler.handle_exception
    def get_access_token(self):

        endpoint = self.apiEndpoints.get_access_token(self.tenant_name)
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        data = {
            "grant_type": "refresh_token",
            "client_id": "ast-app",
            "refresh_token": self.token
        }

        encoded_data = urlencode(data)

        response = self.httpRequest.post_api_request(url, headers, encoded_data)
        print("Successfully generated a token")

        return response.get("access_token")

    @ExceptionHandler.handle_exception
    def get_checkmarx_projects(self, token, base_url, endpoint, empty_tag="false", project_name=None):

        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        limit = 100  
        offset = 0   
        all_projects = []

        while True:
            params = {
                "name": project_name,
                "limit": limit,
                "offset": offset,
                "empty-tags": empty_tag
            }

            response = self.httpRequest.get_api_request(url, headers=headers, params=params)

            if not response or "projects" not in response or not isinstance(response["projects"], list):
                print("Error: 'projects' key missing or not a list in API response")
                return None

            all_projects.extend(response["projects"])

            if len(response["projects"]) < limit:
                break  

            offset += limit

        return all_projects
    
    @ExceptionHandler.handle_exception
    def delete_checkmarx_project(self, token, base_url, endpoint):

        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        response = self.httpRequest.delete_api_request(url, headers=headers)

        return response
    
    @ExceptionHandler.handle_exception
    def update_project_repo_protected_branches(self, token, base_url, endpoint, repo_info, project_id, new_branches):
        
        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        params = {
            "projectId": project_id
        }

        payload = {
            "apiSecScannerEnabled": repo_info.get("apiSecScannerEnabled"),
            "branches": repo_info.get("branches"),
            "containerScannerEnabled": repo_info.get("containerScannerEnabled"),
            "isRepoAdmin": repo_info.get("isRepoAdmin"),
            "kicsScannerEnabled": repo_info.get("kicsScannerEnabled"),
            "ossfSecoreCardScannerEnabled": repo_info.get("ossfSecoreCardScannerEnabled"),
            "prDecorationEnabled": repo_info.get("prDecorationEnabled"),
            "sastIncrementalScan": repo_info.get("sastIncrementalScan"),
            "sastScannerEnabled": repo_info.get("sastScannerEnabled"),
            "scaAutoPrEnabled": repo_info.get("scaAutoPrEnabled"),
            "scaScannerEnabled": repo_info.get("scaScannerEnabled"),
            "secretsDerectionScannerEnabled": repo_info.get("secretsDerectionScannerEnabled"),
            "sshRepoUrl": repo_info.get("sshRepoUrl"),
            "sshState": "SKIPPED",
            "url": repo_info.get("url"),
            "webhookEnabled": repo_info.get("webhookEnabled"),
            "webhookId": repo_info.get("webhookId")
        }

        # Ensure branches list exists
        if "branches" not in payload:
            payload["branches"] = []

        # Convert existing branch names to a set for quick lookup
        existing_branch_names = {branch["name"] for branch in payload["branches"]}

        # Add new branches only if they are not already in the list
        for branch in new_branches:
            if branch not in existing_branch_names:
                payload["branches"].append({
                    "name": branch,
                    "isDefaultBranch": False
                })

        # Send updated repo configuration
        response = self.httpRequest.put_api_request(url, headers=headers, json=payload, params=params)
        return response

    @ExceptionHandler.handle_exception
    def get_project_branches(self, token, base_url, endpoint, project_id, branch_name=None):

        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        params = {
            "project-id": project_id,
            "branch-name": branch_name,
            "limit": 20,
            "offset": 0
        }

        response = self.httpRequest.get_api_request(url, headers=headers, params=params)
        return response

    @ExceptionHandler.handle_exception
    def get_repo_branches(self, token, base_url, endpoint):
        """
        Retrieve all available branches (including paginated results) for a repo.
        """

        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        all_branches = []
        page = 1
        next_page = 1

        while True:
            params = {
                "page": page,
                "nextPageLink": next_page
            }

            response = self.httpRequest.get_api_request(url, headers=headers, params=params)

            if not response or "branchWebDtoList" not in response:
                break

            current_branches = response["branchWebDtoList"]
            all_branches.extend(current_branches)

            if not current_branches:
                break  # No more branches returned

            page += 1
            next_page += 1

        return {"branchWebDtoList": all_branches}
    
    @ExceptionHandler.handle_exception
    def get_project_repo_info(self, token, base_url, endpoint):
        # Use this function if you want to retrieve the list of protected branches
        
        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        response = self.httpRequest.get_api_request(url, headers=headers)
        return response
    
    @ExceptionHandler.handle_exception
    def start_sast_scan(self, token, base_url, endpoint, project_id, api_key, branch=None, repo_url=None):

        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        payload = {
            "project": {
                "id": project_id
            },
            "type": "git",
            "handler": {
                "repoUrl": repo_url,
                "branch": branch,
                "credentials": {
                    "username": "",
                    "type": "apiKey",
                    "value": api_key
                }
            },
            "config": [
                {
                    "type": "sast",
                    "value": {
                        "incremental": "true",
                        "presetName": "Checkmarx Default",
                        "engineVerbose": "false"
                    }
                },
                {
                    "type": "sca",
                    "value": {
                        "lastSastScanTime": "",
                        "exploitablePath": "false"
                    }
                },
                {
                    "type": "microengines",
                    "value": {
                        "scorecard": "false",
                        "2ms": "true"
                    }
                }
            ]
        }

        response = self.httpRequest.post_api_request(url, headers=headers, json=payload)
        return response

    @ExceptionHandler.handle_exception
    def get_project_last_scan(self, token, base_url, endpoint, project_ids):

        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        params = {
            "project-ids": [project_ids]
            # "limit": 100,
            # "offset": 0
        }

        response = self.httpRequest.get_api_request(url, headers=headers, params=params)
        return response

    @ExceptionHandler.handle_exception
    def get_scan_details(self, access_token, scan_id):

        endpoint = self.apiEndpoints.get_scan_details(scan_id)
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        response = self.httpRequest.get_api_request(url, headers=headers)
        return response
    
    @ExceptionHandler.handle_exception
    def get_scan_summary(self, access_token, scan_ids):

        endpoint = self.apiEndpoints.get_scan_summary()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        params = {
            "scan-ids": [scan_ids]
        }

        response = self.httpRequest.get_api_request(url, headers=headers, params=params)
        return response
    
    @ExceptionHandler.handle_exception
    def get_scan_result(self, access_token, scan_id, result_id=None):

        endpoint = self.apiEndpoints.get_scan_results()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        params = {
            "scan-id": scan_id,
            "result_id": result_id
        }

        response = self.httpRequest.get_api_request(url, headers=headers, params=params)
        return response

    @ExceptionHandler.handle_exception
    def get_scans(self, token, base_url, endpoint):

        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        limit = 100  
        offset = 0  
        all_scans = []
        
        while True:
            params = {
                "limit": limit,
                "offset": offset
            }

            response = self.httpRequest.get_api_request(url, headers=headers, params=params)

            if not response or "scans" not in response or not isinstance(response["scans"], list):
                print("Error: 'scans' key missing or not a list in API response")
                return None

            all_scans.extend(response["scans"])

            if len(response["scans"]) < limit:
                break  

            offset += limit

        return all_scans

    @ExceptionHandler.handle_exception
    def get_repo_insights(self, token, base_url, endpoint, repo_url):

        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        payload = {
            "repository_url": repo_url
        }

        response = self.httpRequest.post_api_request(url, headers=headers, json=payload)
        return response

    @ExceptionHandler.handle_exception
    def get_project(self, token, base_url, endpoint):
        
        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        response = self.httpRequest.get_api_request(url, headers=headers)
        return response

    @ExceptionHandler.handle_exception
    def replace_project_tags(self, token, base_url, endpoint, project, tags_dict):
        
        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        project_tags = tags_dict

        payload = {
            "tags": project_tags
        }

        response = self.httpRequest.put_api_request(url, headers=headers, json=payload)
        return response

    @ExceptionHandler.handle_exception
    def update_project_tags_and_criticality(self, token, base_url, endpoint, project, criticality, tags_dict):
        
        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        project_tags = project["tags"]
        project_tags.update(tags_dict)

        payload = {
            "name": project["name"],
            "tags": project_tags,
            "groups": project["groups"],
            "criticality": project["criticality"] if not criticality else criticality,
            "repoUrl": project["repoUrl"],
            "mainBranch": project["mainBranch"]
        }

        response = self.httpRequest.put_api_request(url, headers=headers, json=payload)
        return response
    
    def update_application_tags_and_criticality(self, token, base_url, endpoint, criticality, tag):
        
        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        project_tags = {tag: ""}

        payload = {
            "criticality": criticality,
            "rules": [
                {
                    "type": "project.tag.key.exists",
                    "value": tag
                }
            ],
            "tags": project_tags
        }

        response = self.httpRequest.put_api_request(url, headers=headers, json=payload)
        return response

    @ExceptionHandler.handle_exception
    def create_app_rule(self, token, base_url, endpoint, tag):

        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        payload = {
            "type": "project.tag.key.exists",
            "value": tag
        }

        response = self.httpRequest.post_api_request(url, headers=headers, json=payload)
        return response

    @ExceptionHandler.handle_exception
    def create_application(self, token, base_url, endpoint, app_name, tag, criticality):

        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        payload = {
            "name": app_name,
            "criticality": criticality,
            "tags": {
                tag: ""
            },
            "rules": [
                {
                    "type": "project.tag.key.exists",
                    "value": tag
                }
            ]
        }

        response = self.httpRequest.post_api_request(url, headers=headers, json=payload)
        return response

    @ExceptionHandler.handle_exception_with_retries()
    def get_application_by_name(self, token, base_url, endpoint, app_name):
        
        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        params = {
            "name": app_name
        }

        response = self.httpRequest.get_api_request(url, headers=headers, params=params)
        return response

    @ExceptionHandler.handle_exception
    def get_application_by_id(self, token, base_url, endpoint):
        
        url = f"https://{base_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {token}",
            "Content-Type": "application/json; version=1.0"
        }

        response = self.httpRequest.get_api_request(url, headers=headers)
        return response