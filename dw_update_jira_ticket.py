from jira_utility.jira_api_actions import JiraApiActions
from checkmarx_utility.cx_api_actions import CxApiActions
from checkmarx_utility.helper_functions import HelperFunctions

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

def main():
    
    cx_config_environment = "CX-PRU-NPROD"
    jira_config_environment = "JIRA-EIS"

    jira_api_actions = JiraApiActions(jira_config_environment)
    cx_api_actions = CxApiActions(cx_config_environment)

    access_token = cx_api_actions.get_access_token()

    # date_today = HelperFunctions.get_today_date_yyyymmdd()
    date_today = "20250619"
    
    scans = cx_api_actions.get_scans_by_tags_keys(access_token, date_today)
    scan_list = scans.get("scans", [])

    scan_ids = []
    for scan in scan_list:
        scan_id = scan.get("id")
        if scan_id is not None:
            scan_ids.append(scan_id)

    for scan_id in scan_ids:

        print(f"Scan ID: {scan_id}")
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

        # Create JIRA Issue

        jira_ticket_values= {
            "description": sast_severity_count,
            "summary": scan_id
        }
        
        jira_api_actions.create_issue(jira_ticket_values)

if __name__ == "__main__":
    main()