#!/usr/bin/env python
# coding: utf-8

# In[401]:


import pandas as pd
import requests
import numpy as np
import boto3 as bt
import requests
from ipaddress import ip_address, ip_network
import json
import time
import yaml
import gzip
from datetime import datetime, timedelta

REGION = 'us-east-1'
ACCESS_POINT = 'flaws2-logs'
ACCOUNT_ID = '322079859186'
ACCESS_KEY = 'AKIAIUFNQ2WCOPTEITJQ'
SECRET_KEY = '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'
CONFIG_YAML = './config/config.yaml'
TARGET_PROFILE = 'target_security'

log=logging.basicConfig(filemode='w')
log=logging.getLogger(__name__)
file_handler=logging.FileHandler('cloudtrail.log')
log.addHandler(file_handler)
log.setLevel('DEBUG')

# Set up security profile variables
response = bt.client('sts')
security_id = response.get_caller_identity()

# Set up target_security profile variables
target_session = bt.Session(profile_name=TARGET_PROFILE)
target_client = target_session.client('sts')
target_security_id = target_client.get_caller_identity()

# Download logs
get_ipython().system('aws s3 sync s3://flaws2-logs .')
os.rename('./AWSLogs/653711331788/CloudTrail/us-east-1/', 
          './AWSLogs/653711331788/CloudTrail/us_east_1/')
directory='./AWSLogs/653711331788/CloudTrail/us_east_1/2018/11/28/'
files = [os.path.join(directory,f) for f in os.listdir(directory)]

def whitelisted_ip(whitelist, ip):
    """
    Check ip to see if it is in the whitelist.
    """
    for cidr in whitelist:
        if ip_address(ip) in ip_network(cidr):
            return True
    return False

def add_aws_ips_to_whitelist(config=CONFIG_YAML, service=None, ip_format='ip'):
    """
    Pulling list of AWS's IP ranges to add to whitelist and writes them to a .yaml file. 
    
    config = string
        The /path/to/the/file.yaml file where the whitelist will be held.
    service = string
        Amazon service to filter ips by.  Ex: 'AMAZON','S3','CLOUDWATCH','DYNAMODB'
        if None, will return ips for all services
    format = string
        default is ip_address.  Alternative option is 'ipv6'
        
    """
    if ip_format=='ipv6':
        prefix='ipv6_prefixes'
        ip='ipv6_prefix'
    elif ip_format=='ip':
        prefix = 'prefixes'
        ip='ip_prefix'
    ip_ranges = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json').json()[prefix]
    
    amazon_ips = [item[ip] for item in ip_ranges if item["service"] == "AMAZON"]
    ec2_ips = [item[ip] for item in ip_ranges if item["service"] == "EC2"]
    amazon_ips_less_ec2=[]
    ips={'aws_whitelist_ips':amazon_ips_less_ec2}

    for ip in amazon_ips:
        if ip not in ec2_ips:
            amazon_ips_less_ec2.append(ip)

    with open(config, 'w') as file:
        doc=yaml.dump(ips, file)

# Saving to YAML for ease of adding additional whitelisted ips
add_aws_ips_to_whitelist()

def private_ip_check(ip):
    """
    Check Whitelist for allowed ips
    """
    private = ['100.64.0.0/10', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
    for cidr in private:
        if ip_address(ip) in ip_network(cidr):
            return True
    return False

def check_policy(profile=TARGET_PROFILE):
    """
    Checks the repositories for principal access open to the public
    """
    session = bt.session.Session(aws_access_key_id=ACCESS_KEY,
                  aws_secret_access_key=SECRET_KEY,
                  profile_name=profile)
    target_ecr = target_session.client('ecr')
    for repo in range(len(target_ecr.describe_repositories()['repositories'])):
        target_repo = target_ecr.describe_repositories()['repositories'][repo]['repositoryName']
        target_principal = json.loads(target_ecr.get_repository_policy(repositoryName=target_repo)['policyText'])['Statement'][0]['Principal']
        if target_principal == '*':
            log.warning(f"Warning! Principal access open to the public for repo name: {target_repo}.")


def detect_suspicious_activity(config, files):
    """
    Looks for suspicious IPs from AWS
    
    config = string
        path to config.yaml file containing whitelisted ips
    files = string
        path to cloudtrail log files
    """
    suspicious = []
    api_calls={}
    associate_ips=[]
    with open(config) as f:
        whitelist=yaml.full_load(f)
    
    for file in sorted(files):
        f= None
        log.info(f'Checking File: {file}')
        if file.endswith('.gz'):
            f=gzip.open(file, 'r')
        else:
            f = open(file, 'r')
        try:
            cloudtrail = json.load(f)
        except Exception as e:
            log.error(f'Invalid JSON file: {file} - {e}')
            continue

        records = sorted(cloudtrail['Records'], key=lambda x: datetime.strptime(x['eventTime'], '%Y-%m-%dT%H:%M:%SZ'), reverse=False)
       
        for record in records:
            try:
                if record['eventName'].lower() == 'assumerole': 

                    session_name = record['requestParameters']['roleSessionName']
                    arn = record['requestParameters']['roleArn']
                    account = record['requestParameters']['roleArn'].split(':')[4]
                    role = record['requestParameters']['roleArn'].split('/')[-1]

                    assume_role_session = f'arn:aws:sts::{account}:assumed-role/{role}/{session_name}'

                    if not api_calls.get(session_name, None):
                        api_calls[session_name] = {
                            'source_ip': [],
                            'arn': assume_role_session,
                            'ttl': int(time.time() + 28800)
                        }
                    else:
                        # Set a TTL.  This is most useful in DynamoDB
                        api_calls[session_name]['ttl'] = int(time.time() + 28800)

                if record['userIdentity'].get('type','') == 'AssumedRole':
                    session = record['userIdentity']['arn'].split('/')[-1]
                    
                    # Check for open access in repository
                    check_policy(TARGET_PROFILE)

                    if api_calls.get(session, None):
                        if 'amazonaws' not in record['sourceIPAddress'] and not whitelisted_ip(whitelist.get('aws_whitelist_ips',[]), record['sourceIPAddress']):


                            log.info(f"Outside IP address: {record['sourceIPAddress']} - from eventName: {record['eventName']}")
                            # if this is the first call, we can add this IP to the list                          
                            if len(api_calls[session].get('source_ip',[])) == 0:
                                api_calls[session]['source_ip'].append(record['sourceIPAddress'])                            

                            else:
                                if record['sourceIPAddress'] not in api_calls[session].get('source_ip',[]):
                                    if private_ip_check(record['sourceIPAddress']):
                                        for ip in api_calls[session].get('source_ip',[]):
                                            if private_ip_check(ip):
                                                log.info(f"Multiple IPs for this credential: {assume_role_session} - sourceIP: {record['sourceIPAddress']}")
                                                log.debug(record)
                                                suspicious.append(record)
                                        api_calls[session]['source_ip'].append(record['sourceIPAddress'])
                                        continue

                                    # see if there was a call to change the IP
                                    if session not in associate_ips:
                                        log.info(f"Call to change IP for this credential: {assume_role_session} - sourceIP: {record['sourceIPAddress']}")
                                        log.debug(record)
                                        suspicious.append(record)
            except Exception as e:
                log.fatal(f'Unknown error on record - {record}')
                log.fatal(f'Error - {e}')
                
        f.close()
        
    return suspicious  

detect_suspicious_activity(config=CONFIG_YAML, files= files)


# In[ ]:




