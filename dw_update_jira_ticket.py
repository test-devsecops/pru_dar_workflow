from jira_utility.jira_api_actions import JiraApiActions
from checkmarx_utility.cx_api_actions import CxApiActions

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

def calculate_sum_severity_counters(scan_details):

    critical_total = ""
    high_total = ""
    medium_total = ""
    low_total = ""
    return 

def main():

    # Step 1: Script to look for the scan results with the tag
    # Step 2: Compile the scan IDs
    # Step 3: Loop through the scan IDs and get the details of each scan results
    # Step 4: Collect the summary of the Scan Result (Number of findings per severity)
    # Step 5: Find the Jira Ticket and update it with the collected summary

    #temporary
    scan_id = "8101a57f-3004-4398-bfc4-ea30846ada14"

    # Read JIRA event payload
    with open(os.environ['GITHUB_EVENT_PATH']) as f:
        event = json.load(f)

    payload = event.get("client_payload", {})
    issue_key = payload.get("issue_key", "No issue key")
    summary = payload.get("summary", "No summary provided")
    description = payload.get("description", "No description provided")

    print(f"issue_key: {issue_key}")
    print(f"Summary: {summary}")
    print(f"Description: {description}")
    
    config_environment = "CX-PRU-NPROD"

    # jira_api_actions = JiraApiActions()
    cx_api_actions = CxApiActions()

    access_token = cx_api_actions.get_access_token()

    scan_details = cx_api_actions.get_scan_summary(access_token, scan_id)
    scan_summary = scan_details.get("scansSummaries", [{}])[0]

    # Get SAST scan information
    sast_severity_counters = scan_summary.get("sastCounters", {}).get("severityCounters", {})
    sast_total_count = scan_summary.get("sastCounters", {}).get("totalCounter", {})
    sast_severity_count = get_severity_counts("SAST", sast_severity_counters, sast_total_count)
    
    print(sast_severity_count)

    # Get KICS scan information
    kics_severity_counters = scan_summary.get("kicsCounters", {}).get("severityCounters", {})
    kics_total_count = scan_summary.get("kicsCounters", {}).get("totalCounter", {})
    kics_severity_count = get_severity_counts("KICS", kics_severity_counters, kics_total_count)
    
    print(kics_severity_count)

    # Get SCA scan information
    sca_severity_counters = scan_summary.get("scaCounters", {}).get("severityCounters", {})
    sca_total_count = scan_summary.get("scaCounters", {}).get("totalCounter", {})
    sca_severity_count = get_severity_counts("SCA", sca_severity_counters, sca_total_count)
    
    print(sca_severity_count)

    # Get API Security scan information
    apisec_severity_counters = scan_summary.get("apiSecCounters", {}).get("severityCounters", {})
    apisec_total_count = scan_summary.get("apiSecCounters", {}).get("totalCounter", {})
    apisec_severity_count = get_severity_counts("API-SEC", apisec_severity_counters, apisec_total_count)
    
    print(apisec_severity_count)

    # Get Micro Engines Security scan information
    micro_severity_counters = scan_summary.get("microEnginesCounters", {}).get("severityCounters", {})
    micro_total_count = scan_summary.get("microEnginesCounters", {}).get("totalCounter", {})
    micro_severity_count = get_severity_counts("MICRO-ENG", micro_severity_counters, micro_total_count)
    
    print(micro_severity_count)

    # Get Container Security scan information
    container_severity_counters = scan_summary.get("containersCounters", {}).get("severityCounters", {})
    container_total_count = scan_summary.get("containersCounters", {}).get("totalCounter", {})
    container_severity_count = get_severity_counts("CONTAINER", container_severity_counters, container_total_count)
    
    print(container_severity_count)

    # requests_results = jira_api_actions.get_queues()
    # print(requests_results)

if __name__ == "__main__":
    main()