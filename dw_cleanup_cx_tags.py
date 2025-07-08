from jira_utility.jira_api_actions import JiraApiActions
from checkmarx_utility.cx_api_actions import CxApiActions
from checkmarx_utility.helper_functions import HelperFunctions
from checkmarx_utility.cx_config_utility import Config

from utils.logger import Logger

import os
import sys
import argparse
import re
import time
import json

def get_severity_counts(scanner, severity_counters, total_count):
    result = {}
    
    if not severity_counters:
        # All severities are 0 if severity_counters is empty
        severities = ["HIGH", "MEDIUM", "LOW", "INFO"]
        for severity in severities:
            result[f"{scanner}_{severity}"] = 0
        result["TOTAL_COUNT"] = 0
        return result

    # Populate based on actual severity_counters
    for item in severity_counters:
        severity = item.get("severity", "").upper()
        count = item.get("counter", 0)
        result[f"{scanner}_{severity}"] = count

    result["TOTAL_COUNT"] = total_count
    return result 

def get_total_by_severity(scan_types : list) -> dict :
    scan_types_list = scan_types
    
    # Initialize severity
    severity_result = {'critical': 0, 'high': 0, 'medium': 0, 'low':0, 'info' : 0}

    for scan in scan_types_list:
        for severityObj in scan:
            severity = severityObj.get('severity').lower()
            count = severityObj.get('counter')

            severity_result[severity] += count
                
        
    return severity_result 

def assemble_url_link(url :str, scan_data : dict ) -> str:
    url_string = url
    project_id = scan_data.get('projectId')
    scan_id = scan_data.get('id')
    branch = scan_data.get('branch')

    return f"https://{url_string}/projects/{project_id}/scans?id={scan_id}&branch={branch}"


def main():
    
    cx_config_environment = "CX-PRU-NPROD"
    jira_config_environment = "JIRA-EIS"

    jira_api_actions = JiraApiActions(jira_config_environment)
    cx_api_actions = CxApiActions(cx_config_environment)

    access_token = cx_api_actions.get_access_token()
    tag_query = { 
        "tags-keys": ["DAR"],
        "tags-values" : ["DONE"]
        }

    scans = cx_api_actions.get_scans_by_tags_keys(access_token, tag_query)
    scan_list = scans.get("scans", [])

    for scan_data in scan_list:
        scan_id = scan_data.get("id")
        scan_tags = scan_data.get("tags")

        removed_tag = scan_tags.pop("DAR", None)
        if removed_tag is None:
            print("Tag is unavailable")

        tag_update_response = cx_api_actions.update_scan_tags(access_token, scan_id, tags_dict=scan_tags)

if __name__ == "__main__":
    main()