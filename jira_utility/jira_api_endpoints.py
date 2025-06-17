class JiraApiEndpoints:

    @staticmethod
    def get_queues(project_id):
        endpoint = f"/rest/servicedeskapi/servicedesk/{project_id}/queue"
        return endpoint