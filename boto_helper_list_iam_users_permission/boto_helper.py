import boto3
import os
# import hvac
import warnings
import botocore
# from dotenv import load_dotenv


# load_dotenv()
warnings.filterwarnings("ignore")


class BotoHelper:
    def create_boto_session(self, profile_name=None):
        '''Creates and returns a boto session using current AWS_PROFILE'''
        try:
            if profile_name is None:
                session = boto3.session.Session(
                    aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
                    aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
                    aws_session_token=os.environ['AWS_SESSION_TOKEN'],
                    region_name=os.environ['AWS_REGION']
                )
            else:
                session = boto3.session.Session(profile_name=profile_name)
        except botocore.exceptions.ProfileNotFound as e:
            return "The provided profile cannot be found in your AWS Credentials"
        except botocore.exceptions.ClientError as e:
            raise e
        return session

    def get_boto_client(self, session, service, region_name=None):
        '''Creates and returns a boto client for a specific AWS service and region'''
        try:
            client = session.client(service, region_name=region_name, verify=False)
        except botocore.exceptions.ClientError as e:
            raise e
        return client

    def assume_role(self, session, account_id, role_name, session_name):
        '''Assumes a role in another aws account and returns a boto session in that account'''
        try:
            sts = self.get_boto_client(session, 'sts')
            credentials = sts.assume_role(
                RoleArn='arn:aws:iam::' + str(account_id) + ':role/' + role_name,
                RoleSessionName=session_name
            )
            assumed_session = boto3.session.Session(
                aws_access_key_id=credentials['Credentials']['AccessKeyId'],
                aws_secret_access_key=credentials['Credentials']['SecretAccessKey'],
                aws_session_token=credentials['Credentials']['SessionToken']
            )
            return(assumed_session)
        except botocore.exceptions.ClientError as e:
            print(f'Error: Could not assume {role_name} in {str(account_id)}')
            return('Error')

    def get_credentials_with_vault(self, vault_role_name):
        '''Authenticates with Vault and adds credentials to AWS Profile.
            Requires a .env document to store VAULT_URL, VAULT_NAMESPACE,
            VAULT_ROLE_ID, and SECRET_ID.
        '''
        client = hvac.Client(
            url=os.getenv('VAULT_URL'),
            verify=False,
            namespace=os.getenv('VAULT_NAMESPACE'),
        )

        client.auth_approle(
            role_id=os.getenv('VAULT_ROLE_ID'),
            secret_id=os.getenv('SECRET_ID')
        )

        credentials = client.secrets.aws.generate_credentials(
            name=vault_role_name
        )

        access_key_id = credentials['data']['access_key']
        secret_access_key = credentials['data']['secret_key']
        session_token = credentials['data']['security_token']

        return(access_key_id, secret_access_key, session_token)

    def set_aws_credentials_env_variables(self, access_key_id, secret_access_key, session_token):
        os.environ['AWS_ACCESS_KEY_ID'] = access_key_id
        os.environ['AWS_SECRET_ACCESS_KEY'] = secret_access_key
        os.environ['AWS_SESSION_TOKEN'] = session_token
        os.environ['AWS_REGION'] = 'us-east-1'

    def set_vault_proxies(self):
        os.environ['HTTP_PROXY'] = os.getenv('VAULT_HTTP_PROXY')
        os.environ['HTTPS_PROXY'] = os.getenv('VAULT_HTTPS_PROXY')
        os.environ['NO_PROXY'] = os.getenv('NO_PROXY')
        os.environ['http_proxy'] = os.getenv('VAULT_HTTP_PROXY')
        os.environ['https_proxy'] = os.getenv('VAULT_HTTPS_PROXY')
        os.environ['no_proxy'] = os.getenv('NO_PROXY')

    def set_aws_proxies(self):
        os.environ['HTTP_PROXY'] = os.getenv('AWS_HTTP_PROXY')
        os.environ['HTTPS_PROXY'] = os.getenv('AWS_HTTPS_PROXY')
        os.environ['http_proxy'] = os.getenv('AWS_HTTP_PROXY')
        os.environ['https_proxy'] = os.getenv('AWS_HTTPS_PROXY')

    def extract_identity_from_session(self, session):
        '''Extract the identity from the provided session. Can be used to assert that a role switch worked as expected.'''
        try:
            client = self.get_boto_client(session, 'sts')
            identity = client.get_caller_identity()["Arn"]
            print(identity)
        except Exception as e:
            raise e
        return identity