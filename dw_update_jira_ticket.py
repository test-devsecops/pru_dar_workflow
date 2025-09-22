from jira_utility.jira_api_actions import JiraApiActions
from checkmarx_utility.cx_api_actions import CxApiActions
from checkmarx_utility.helper_functions import HelperFunctions
from checkmarx_utility.cx_config_utility import Config
import urllib

from utils.logger import Logger

import os
import sys
import argparse
import re
import time
import json
import uuid

engine_endpoints = {
    "sast" : "sast-results",
    "sca" : "sca",
    "apisec" : "apisec",
    "containers" : "container-security-results",
    "kics" : "kics",
    "microengines" : "supply-chain" # scs
}

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
    branch = urllib.parse.quote_plus(scan_data.get('branch'))
    
    return f"https://{url_string}/projects/{project_id}/scans?branch={branch}&id={scan_id}"

def assemble_scan_individual_link(scan_endpoint: str, url :str, scan_data : dict ) -> str:
    url_string = url
    project_id = scan_data.get('projectId')
    scan_id = scan_data.get('id')
    branch = urllib.parse.quote_plus(scan_data.get('branch'))

    alternate_links_scans = ["apisec","kics"]

    if scan_endpoint in alternate_links_scans:
        return f"https://{url_string}/results/{scan_id}/{project_id}/{scan_endpoint}"
    
    if scan_endpoint == 'sca':
        return f"https://{url_string}/results/{project_id}/{scan_id}/sca?internalPath=%2Fpackages"

    return f"https://{url_string}/{scan_endpoint}/{project_id}/{scan_id}"


def url_links_for_all_scans(all_scan_data : list):
    print()
    for scan_type in all_scan_data:
        print(scan_type)

def create_url_links(scan_data : list, engine_endpoints: dict, url: str) -> list:
    scan_engines = scan_data.get("engines")

    scan_engine_links = []
    for scan in scan_engines:
        try:
            if scan not in engine_endpoints:
                raise ValueError(f"Unknown Engine - {scan}")
            scan_engine_links.append(assemble_scan_individual_link(scan_endpoint=engine_endpoints.get(scan),
                                                                url=url,
                                                                scan_data=scan_data))
        except ValueError as e:
            print(f"Caught Error on creating URL Links: {e}")
    # return scan_engine_links[0]
    return "\n".join(scan_engine_links)

def beautify_description(dict : dict):
    return '\n'.join(f'{k}: {v}' for k, v in dict.items())

def main():

    scan_id = sys.argv[1]
    commit_id = sys.argv[2]
    csec_scan_id = sys.argv[3]
    csec_commit_id = sys.argv[4]
    dast_scan_id = sys.argv[5]
    dast_commit_id = sys.argv[6]
    jira_issue_id = sys.argv[7]

    print("jira_issue_id: ",jira_issue_id)
    print("sast_scan_id :", scan_id)
    print("sast_commit_id :" ,commit_id)
    print("csec_scan_id: ",csec_scan_id)
    print("csec_commit_id :", csec_commit_id)
    print("dast_scan_id :" ,dast_scan_id)
    print("dast_commit_id :" ,dast_commit_id)
    
    cx_config_environment = "CX-PRU-NPROD"
    jira_config_environment = "JIRA-EIS"

    jira_api_actions = JiraApiActions(jira_config_environment)
    cx_api_actions = CxApiActions(cx_config_environment)

    print("Retrieving access_token")
    access_token = cx_api_actions.get_access_token()
    print("Retrieving Scan Summary")
    scan_summary = cx_api_actions.get_scan_summary(access_token, scan_id)

    print("Retrieving Scan Details")
    scan_details = cx_api_actions.get_scan_details(access_token, scan_id=scan_id)
    project_id = scan_details.get("projectId")
    # print(scan_details)

    print("Retrieving Scan Metadata")
    scan_metadata = cx_api_actions.get_scan_metadata(access_token, scan_id=scan_id)
    is_incremental = False
    scan_type = ""

    if 'missing' in scan_metadata:
        is_incremental = False
    elif 'scans' in scan_metadata:
        scan_check = scan_metadata.get('scans')
        is_incremental = scan_check.pop().get('isIncremental')
    
    if is_incremental:
        scan_type = "Incremental Scan"
    else:
        scan_type = "Full Scan"

    # print(scan_type)
    # print(scan_details)
    
    # all_scan_urls = url_links_for_all_scans(all_scans_details)
    scan_summary = scan_summary.get("scansSummaries", [{}])[0]

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
    project_tags = project_info.get("tags", {})
    project_tags = list(project_tags.keys())
    applications = []
    
    for app in application_ids:
        application_info = cx_api_actions.get_application_by_id(access_token, app)
        applications.append(application_info.get("name"))

    if applications:
        application = ", ".join(applications)
    
    description = {
            "Branch" : scan_details.get("branch",""),
            "Scan Origin": scan_details.get("sourceOrigin",""),
            "Scan Type": scan_type, 
            "Status" : scan_details.get("status",""),
            # "Scan ID": scan_id,
            # "Scan URL" : create_url_links(scan_data=scan_details, engine_endpoints=engine_endpoints, url=cx_api_actions.get_tenant_url()) 
        }
    description = beautify_description(description)

    # Create JIRA Issue
    jira_ticket_values= {
        "issue_id" : jira_issue_id,
        "description": description,
        "commit_id" : commit_id,
        "scan_id" : scan_id,
        "summary": scan_details.get('projectName'),
        "lbu": HelperFunctions.get_lbu_name_simple(scan_details.get('projectName')),
        "project_name" : scan_details.get('projectName'),
        "application_name" : application,
        "scan_report_link" : assemble_url_link(url = cx_api_actions.get_tenant_url(), scan_data = scan_details), 
        "num_of_critical" : severity_total.get('critical',0),
        "num_of_high" : severity_total.get('high',0),
        "num_of_medium" : severity_total.get('medium',0),
        "num_of_low" : severity_total.get('low',0),
        "tag" : ",".join(project_tags),
        "scan_url" :  create_url_links(scan_data=scan_details, engine_endpoints=engine_endpoints, url=cx_api_actions.get_tenant_url()),
    }

    # print(json.dumps(jira_ticket_values, indent=1))

    print("Creating Jira Issue")
    create_issue = jira_api_actions.create_issue(jira_ticket_values)

    scan_tags = {}

    scan_tags[jira_issue_id] = commit_id 

    print("Tagging Scan on Checkmarx")
    tag_update_response = cx_api_actions.update_scan_tags(access_token, scan_id, tags_dict=scan_tags)


if __name__ == "__main__":
    main()