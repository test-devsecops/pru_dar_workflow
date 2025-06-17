class CxApiEndpoints:

    @staticmethod
    def get_access_token(tenant_name):
        endpoint = f"/auth/realms/{tenant_name}/protocol/openid-connect/token"
        return endpoint

    @staticmethod
    def get_checkmarx_projects():
        endpoint = "/api/projects/"
        return endpoint

    @staticmethod
    def get_project_last_scan():
        endpoint = "/api/projects/last-scan"
        return endpoint
    
    @staticmethod
    def start_scans():
        endpoint = "/api/scans/"
        return endpoint

    @staticmethod
    def get_scans():
        endpoint = "/api/scans/"
        return endpoint

    @staticmethod
    def get_scan_details(scan_id):
        endpoint = f"/api/scans/{scan_id}"
        return endpoint
    
    @staticmethod
    def get_scan_summary():
        endpoint = f"/api/scan-summary"
        return endpoint

    @staticmethod
    def get_sast_results():
        endpoint = f"/api/sast-results"
        return endpoint

    # Use this route/endpint if you want to retrieve the list of protected branches.
    @staticmethod
    def get_project_repo(repo_id):
        endpoint = f"/api/repos-manager/repo/{repo_id}"
        return endpoint

    # Use this route/endpint if you want to retrieve the list of scanned branches.
    @staticmethod
    def get_project_branches():
        endpoint = "/api/projects/branches"
        return endpoint

    # Use this route/endpint if you want to retrieve the list of branches available to be set as protected branches.
    @staticmethod
    def get_repo_branches(repo_id):
        endpoint = f"/api/repos-manager/repos/{repo_id}/branches"
        return endpoint

    @staticmethod
    def get_repos_by_project_id(project_id):
        endpoint = f"/api/insights/project/{project_id}"
        return endpoint

    @staticmethod
    def get_repo_insights():
        endpoint = "/api/insights/repository"
        return endpoint

    @staticmethod
    def get_project(project_id):
        endpoint = f"/api/projects/{project_id}"
        return endpoint

    @staticmethod
    def delete_project(project_id):
        endpoint = f"/api/projects/{project_id}"
        return endpoint
    
    @staticmethod
    def update_projects(project_id):
        endpoint = f"/api/projects/{project_id}"
        return endpoint

    @staticmethod
    def create_application():
        endpoint = "/api/applications/"
        return endpoint

    @staticmethod
    def get_application():
        endpoint = "/api/applications/"
        return endpoint

    @staticmethod
    def get_application_by_id(application_id):
        endpoint = f"/api/applications/{application_id}"
        return endpoint
    
    @staticmethod
    def update_application(application_id):
        endpoint = f"/api/applications/{application_id}"
        return endpoint

    @staticmethod
    def create_app_rule(application_id):
        endpoint = f"/api/applications/{application_id}/projects"
        return endpoint