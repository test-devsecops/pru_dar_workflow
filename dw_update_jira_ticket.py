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
        "tags-values" : [""]
        }

    scans = cx_api_actions.get_scans_by_tags_keys(access_token, tag_query)
    scan_list = scans.get("scans", [])

    for scan_data in scan_list:
        scan_id = scan_data.get("id")
        project_id = scan_data.get("projectId")
        scan_tags = scan_data.get("tags")
        

        print(f"Scan ID: {scan_id}")
        scan_details = cx_api_actions.get_scan_summary(access_token, scan_id)
        scan_summary = scan_details.get("scansSummaries", [{}])[0]

        # Get SAST scan information
        sast_severity_counters = scan_summary.get("sastCounters", {}).get("severityCounters", {})
        sast_total_count = scan_summary.get("sastCounters", {}).get("totalCounter", {})
        sast_severity_count = get_severity_counts("SAST", sast_severity_counters, sast_total_count)
        
        # print(sast_severity_count)

        # Get KICS scan information
        kics_severity_counters = scan_summary.get("kicsCounters", {}).get("severityCounters", {})
        kics_total_count = scan_summary.get("kicsCounters", {}).get("totalCounter", {})
        kics_severity_count = get_severity_counts("KICS", kics_severity_counters, kics_total_count)
        
        # print(kics_severity_count)

        # Get SCA scan information
        sca_severity_counters = scan_summary.get("scaCounters", {}).get("severityCounters", {})
        sca_total_count = scan_summary.get("scaCounters", {}).get("totalCounter", {})
        sca_severity_count = get_severity_counts("SCA", sca_severity_counters, sca_total_count)
        
        # print(sca_severity_count)

        # Get API Security scan information
        apisec_severity_counters = scan_summary.get("apiSecCounters", {}).get("severityCounters", {})
        apisec_total_count = scan_summary.get("apiSecCounters", {}).get("totalCounter", {})
        apisec_severity_count = get_severity_counts("API-SEC", apisec_severity_counters, apisec_total_count)
        
        # print(apisec_severity_count)

        # Get Micro Engines Security scan information
        micro_severity_counters = scan_summary.get("microEnginesCounters", {}).get("severityCounters", {})
        micro_total_count = scan_summary.get("microEnginesCounters", {}).get("totalCounter", {})
        micro_severity_count = get_severity_counts("MICRO-ENG", micro_severity_counters, micro_total_count)
        
        # print(micro_severity_count)

        # Get Container Security scan information
        container_severity_counters = scan_summary.get("containersCounters", {}).get("severityCounters", {})
        container_total_count = scan_summary.get("containersCounters", {}).get("totalCounter", {})
        container_severity_count = get_severity_counts("CONTAINER", container_severity_counters, container_total_count)

        # print(container_severity_count)

        severity_total = get_total_by_severity([sast_severity_counters,
                                                kics_severity_counters,
                                                sca_severity_counters,
                                                apisec_severity_counters,
                                                micro_severity_counters, 
                                                container_severity_counters])
        
        project_info = cx_api_actions.get_project_info_by_id(access_token, project_id)


        application = "Unavailable"
        application_ids = project_info.get('applicationIds', [])
        applications = []
        
        for app in application_ids:
            application_info = cx_api_actions.get_application_by_id(access_token, app)
            applications.append(application_info.get("name"))

        if applications:
            application = ", ".join(applications)

        # Create JIRA Issue
        jira_ticket_values= {
            "description": "",
            "summary": scan_id,
            "lbu": HelperFunctions.get_lbu_name_simple(scan_data.get('projectName')),
            "project_name" : scan_data.get('projectName'),
            "application_name" : application,
            "scan_report_link" : assemble_url_link(url = cx_api_actions.get_tenant_url(), scan_data = scan_data), 
            "num_of_critical" : severity_total.get('critical'),
            "num_of_high" : severity_total.get('high'),
            "num_of_medium" : severity_total.get('medium'),
            "num_of_low" : severity_total.get('low') 
        }

        
        # jira_api_actions.create_issue(jira_ticket_values)

        scan_tags["DAR"] = "DONE"

        tag_update_response = cx_api_actions.update_scan_tags(access_token, scan_id, tags_dict=scan_tags)

if __name__ == "__main__":
    main()