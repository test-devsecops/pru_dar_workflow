import configparser
import os
import sys

class Config:
    
    def __init__(self, config_file=None):
        """Initialize and load the config.env file."""
        self.config_file = config_file or os.path.join(os.path.dirname(__file__), '..', 'config_dev.env')
        self.config = configparser.ConfigParser()
        self.config.read(self.config_file)

    def get_config(self, section):
        """Retrieve environment variables from a specific section in the .env file."""
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