import configparser
import os
import sys

class Config:
    
    def __init__(self, config_file=None):
        """Load from environment variables first, fallback to config file."""
        self.token = os.getenv('CX_TOKEN')
        self.tenant_name = os.getenv('TENANT_NAME')
        self.tenant_iam_url = os.getenv('TENANT_IAM_URL')
        self.tenant_url = os.getenv('TENANT_URL')

        if all([self.token, self.tenant_name, self.tenant_iam_url, self.tenant_url]):
            # All vars loaded from environment, skip file loading
            return

        # Fallback to config file
        self.config_file = config_file or os.path.join(os.path.dirname(__file__), '..', 'config_dev.env')
        self.config = configparser.ConfigParser()
        self.config.read(self.config_file)

    def get_config(self, section):
        """Return config values either from env or file."""
        if self.token and self.tenant_name and self.tenant_iam_url and self.tenant_url:
            return self.token, self.tenant_name, self.tenant_iam_url, self.tenant_url

        if section not in self.config:
            print(f"Error: Section [{section}] not found in {self.config_file}")
            sys.exit(1)

        try:
            token = self.config[section]['CX_TOKEN']
            tenant_name = self.config[section]['TENANT_NAME']
            tenant_iam_url = self.config[section]['TENANT_IAM_URL']
            tenant_url = self.config[section]['TENANT_URL']
        except KeyError as e:
            print(f"Error: Missing key {e} in section [{section}] of {self.config_file}")
            sys.exit(1)

        return token, tenant_name, tenant_iam_url, tenant_url
