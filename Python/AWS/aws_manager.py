#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWS Manager - Comprehensive AWS Resource Management

This script provides comprehensive AWS resource management capabilities including:
- EC2 instance management (create, start, stop, terminate)
- S3 bucket operations (create, list, upload, download)
- IAM user and role management
- Lambda function deployment and management
- CloudFormation stack operations
- Cost analysis and reporting
- Security group management
- Auto Scaling group management
- RDS database operations
- CloudWatch monitoring and alerts

Author: System Administrator
Version: 1.0.0
Date: 2024-01-01
"""

import os
import sys
import json
import logging
import argparse
import boto3
import botocore
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import yaml
from botocore.exceptions import ClientError, NoCredentialsError


class AWSManager:
    """Comprehensive AWS resource management"""
    
    def __init__(self, config: Dict = None):
        """Initialize the AWS manager"""
        self.config = config or {}
        self.logger = self._setup_logging()
        
        # Initialize AWS clients
        self._setup_aws_clients()
        
        # Default settings
        self.default_region = self.config.get('default_region', 'us-east-1')
        self.default_vpc_id = self.config.get('default_vpc_id')
        self.default_subnet_id = self.config.get('default_subnet_id')
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('AWSManager')
        logger.setLevel(logging.INFO)
        
        # Create handlers
        console_handler = logging.StreamHandler()
        file_handler = logging.FileHandler('aws_manager.log')
        
        # Create formatters and add it to handlers
        log_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(log_format)
        file_handler.setFormatter(log_format)
        
        # Add handlers to the logger
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        
        return logger
    
    def _setup_aws_clients(self):
        """Setup AWS service clients"""
        try:
            # Core services
            self.ec2_client = boto3.client('ec2', region_name=self.default_region)
            self.s3_client = boto3.client('s3', region_name=self.default_region)
            self.iam_client = boto3.client('iam', region_name=self.default_region)
            self.lambda_client = boto3.client('lambda', region_name=self.default_region)
            self.cloudformation_client = boto3.client('cloudformation', region_name=self.default_region)
            self.cloudwatch_client = boto3.client('cloudwatch', region_name=self.default_region)
            self.rds_client = boto3.client('rds', region_name=self.default_region)
            self.autoscaling_client = boto3.client('autoscaling', region_name=self.default_region)
            self.ce_client = boto3.client('ce', region_name=self.default_region)
            
            # Test connection
            self.ec2_client.describe_regions()
            self.logger.info("AWS clients initialized successfully")
            
        except NoCredentialsError:
            self.logger.error("AWS credentials not found. Please configure AWS credentials.")
            raise
        except Exception as e:
            self.logger.error(f"Error initializing AWS clients: {e}")
            raise
    
    # EC2 Management
    def list_instances(self, filters: Dict = None) -> List[Dict]:
        """List EC2 instances"""
        try:
            response = self.ec2_client.describe_instances(Filters=filters or [])
            instances = []
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_info = {
                        'id': instance['InstanceId'],
                        'type': instance['InstanceType'],
                        'state': instance['State']['Name'],
                        'launch_time': instance['LaunchTime'].isoformat(),
                        'public_ip': instance.get('PublicIpAddress'),
                        'private_ip': instance.get('PrivateIpAddress'),
                        'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    }
                    instances.append(instance_info)
            
            self.logger.info(f"Found {len(instances)} instances")
            return instances
            
        except Exception as e:
            self.logger.error(f"Error listing instances: {e}")
            return []
    
    def create_instance(self, instance_config: Dict) -> Dict:
        """Create EC2 instance"""
        try:
            self.logger.info(f"Creating instance with config: {instance_config}")
            
            # Prepare launch configuration
            launch_config = {
                'ImageId': instance_config['image_id'],
                'InstanceType': instance_config['instance_type'],
                'MinCount': 1,
                'MaxCount': 1,
                'SecurityGroupIds': instance_config.get('security_groups', []),
                'SubnetId': instance_config.get('subnet_id', self.default_subnet_id),
                'KeyName': instance_config.get('key_name'),
                'UserData': instance_config.get('user_data', ''),
                'TagSpecifications': [{
                    'ResourceType': 'instance',
                    'Tags': instance_config.get('tags', [])
                }]
            }
            
            response = self.ec2_client.run_instances(**launch_config)
            instance_id = response['Instances'][0]['InstanceId']
            
            self.logger.info(f"Instance created: {instance_id}")
            return {'instance_id': instance_id, 'status': 'creating'}
            
        except Exception as e:
            self.logger.error(f"Error creating instance: {e}")
            return {}
    
    def start_instance(self, instance_id: str) -> bool:
        """Start EC2 instance"""
        try:
            self.ec2_client.start_instances(InstanceIds=[instance_id])
            self.logger.info(f"Instance started: {instance_id}")
            return True
        except Exception as e:
            self.logger.error(f"Error starting instance {instance_id}: {e}")
            return False
    
    def stop_instance(self, instance_id: str) -> bool:
        """Stop EC2 instance"""
        try:
            self.ec2_client.stop_instances(InstanceIds=[instance_id])
            self.logger.info(f"Instance stopped: {instance_id}")
            return True
        except Exception as e:
            self.logger.error(f"Error stopping instance {instance_id}: {e}")
            return False
    
    def terminate_instance(self, instance_id: str) -> bool:
        """Terminate EC2 instance"""
        try:
            self.ec2_client.terminate_instances(InstanceIds=[instance_id])
            self.logger.info(f"Instance terminated: {instance_id}")
            return True
        except Exception as e:
            self.logger.error(f"Error terminating instance {instance_id}: {e}")
            return False
    
    # S3 Management
    def list_buckets(self) -> List[Dict]:
        """List S3 buckets"""
        try:
            response = self.s3_client.list_buckets()
            buckets = []
            
            for bucket in response['Buckets']:
                bucket_info = {
                    'name': bucket['Name'],
                    'creation_date': bucket['CreationDate'].isoformat(),
                    'region': self.s3_client.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint'] or 'us-east-1'
                }
                buckets.append(bucket_info)
            
            self.logger.info(f"Found {len(buckets)} buckets")
            return buckets
            
        except Exception as e:
            self.logger.error(f"Error listing buckets: {e}")
            return []
    
    def create_bucket(self, bucket_name: str, region: str = None) -> bool:
        """Create S3 bucket"""
        try:
            if not region:
                region = self.default_region
            
            if region == 'us-east-1':
                self.s3_client.create_bucket(Bucket=bucket_name)
            else:
                self.s3_client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': region}
                )
            
            self.logger.info(f"Bucket created: {bucket_name} in {region}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating bucket {bucket_name}: {e}")
            return False
    
    def upload_file(self, bucket_name: str, file_path: str, object_key: str = None) -> bool:
        """Upload file to S3"""
        try:
            if not object_key:
                object_key = Path(file_path).name
            
            self.s3_client.upload_file(file_path, bucket_name, object_key)
            self.logger.info(f"File uploaded: {file_path} -> s3://{bucket_name}/{object_key}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error uploading file {file_path}: {e}")
            return False
    
    def download_file(self, bucket_name: str, object_key: str, local_path: str) -> bool:
        """Download file from S3"""
        try:
            self.s3_client.download_file(bucket_name, object_key, local_path)
            self.logger.info(f"File downloaded: s3://{bucket_name}/{object_key} -> {local_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error downloading file {object_key}: {e}")
            return False
    
    def list_objects(self, bucket_name: str, prefix: str = '') -> List[Dict]:
        """List objects in S3 bucket"""
        try:
            response = self.s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
            objects = []
            
            for obj in response.get('Contents', []):
                object_info = {
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'last_modified': obj['LastModified'].isoformat(),
                    'storage_class': obj['StorageClass']
                }
                objects.append(object_info)
            
            self.logger.info(f"Found {len(objects)} objects in bucket {bucket_name}")
            return objects
            
        except Exception as e:
            self.logger.error(f"Error listing objects in bucket {bucket_name}: {e}")
            return []
    
    # IAM Management
    def list_users(self) -> List[Dict]:
        """List IAM users"""
        try:
            response = self.iam_client.list_users()
            users = []
            
            for user in response['Users']:
                user_info = {
                    'username': user['UserName'],
                    'user_id': user['UserId'],
                    'arn': user['Arn'],
                    'create_date': user['CreateDate'].isoformat(),
                    'path': user['Path']
                }
                users.append(user_info)
            
            self.logger.info(f"Found {len(users)} IAM users")
            return users
            
        except Exception as e:
            self.logger.error(f"Error listing IAM users: {e}")
            return []
    
    def create_user(self, username: str, path: str = '/') -> bool:
        """Create IAM user"""
        try:
            self.iam_client.create_user(UserName=username, Path=path)
            self.logger.info(f"IAM user created: {username}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating IAM user {username}: {e}")
            return False
    
    def delete_user(self, username: str) -> bool:
        """Delete IAM user"""
        try:
            # Detach all policies first
            attached_policies = self.iam_client.list_attached_user_policies(UserName=username)
            for policy in attached_policies['AttachedPolicies']:
                self.iam_client.detach_user_policy(
                    UserName=username,
                    PolicyArn=policy['PolicyArn']
                )
            
            # Delete user
            self.iam_client.delete_user(UserName=username)
            self.logger.info(f"IAM user deleted: {username}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting IAM user {username}: {e}")
            return False
    
    # Lambda Management
    def list_functions(self) -> List[Dict]:
        """List Lambda functions"""
        try:
            response = self.lambda_client.list_functions()
            functions = []
            
            for function in response['Functions']:
                function_info = {
                    'name': function['FunctionName'],
                    'arn': function['FunctionArn'],
                    'runtime': function['Runtime'],
                    'handler': function['Handler'],
                    'code_size': function['CodeSize'],
                    'description': function.get('Description', ''),
                    'timeout': function['Timeout'],
                    'memory_size': function['MemorySize'],
                    'last_modified': function['LastModified']
                }
                functions.append(function_info)
            
            self.logger.info(f"Found {len(functions)} Lambda functions")
            return functions
            
        except Exception as e:
            self.logger.error(f"Error listing Lambda functions: {e}")
            return []
    
    def create_function(self, function_config: Dict) -> Dict:
        """Create Lambda function"""
        try:
            self.logger.info(f"Creating Lambda function: {function_config['name']}")
            
            # Prepare function configuration
            function_params = {
                'FunctionName': function_config['name'],
                'Runtime': function_config['runtime'],
                'Handler': function_config['handler'],
                'Role': function_config['role_arn'],
                'Code': {
                    'ZipFile': function_config['code']
                },
                'Description': function_config.get('description', ''),
                'Timeout': function_config.get('timeout', 3),
                'MemorySize': function_config.get('memory_size', 128)
            }
            
            response = self.lambda_client.create_function(**function_params)
            
            self.logger.info(f"Lambda function created: {response['FunctionName']}")
            return {
                'function_name': response['FunctionName'],
                'function_arn': response['FunctionArn'],
                'status': response['State']
            }
            
        except Exception as e:
            self.logger.error(f"Error creating Lambda function: {e}")
            return {}
    
    def delete_function(self, function_name: str) -> bool:
        """Delete Lambda function"""
        try:
            self.lambda_client.delete_function(FunctionName=function_name)
            self.logger.info(f"Lambda function deleted: {function_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting Lambda function {function_name}: {e}")
            return False
    
    # CloudFormation Management
    def list_stacks(self) -> List[Dict]:
        """List CloudFormation stacks"""
        try:
            response = self.cloudformation_client.list_stacks()
            stacks = []
            
            for stack in response['StackSummaries']:
                stack_info = {
                    'name': stack['StackName'],
                    'id': stack['StackId'],
                    'status': stack['StackStatus'],
                    'creation_time': stack['CreationTime'].isoformat(),
                    'description': stack.get('TemplateDescription', '')
                }
                stacks.append(stack_info)
            
            self.logger.info(f"Found {len(stacks)} CloudFormation stacks")
            return stacks
            
        except Exception as e:
            self.logger.error(f"Error listing CloudFormation stacks: {e}")
            return []
    
    def create_stack(self, stack_name: str, template_url: str, parameters: List[Dict] = None) -> Dict:
        """Create CloudFormation stack"""
        try:
            self.logger.info(f"Creating CloudFormation stack: {stack_name}")
            
            stack_params = {
                'StackName': stack_name,
                'TemplateURL': template_url,
                'Capabilities': ['CAPABILITY_IAM']
            }
            
            if parameters:
                stack_params['Parameters'] = parameters
            
            response = self.cloudformation_client.create_stack(**stack_params)
            
            self.logger.info(f"CloudFormation stack created: {response['StackId']}")
            return {
                'stack_id': response['StackId'],
                'stack_name': stack_name,
                'status': 'CREATE_IN_PROGRESS'
            }
            
        except Exception as e:
            self.logger.error(f"Error creating CloudFormation stack: {e}")
            return {}
    
    def delete_stack(self, stack_name: str) -> bool:
        """Delete CloudFormation stack"""
        try:
            self.cloudformation_client.delete_stack(StackName=stack_name)
            self.logger.info(f"CloudFormation stack deleted: {stack_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting CloudFormation stack {stack_name}: {e}")
            return False
    
    # Cost Analysis
    def get_cost_analysis(self, start_date: str, end_date: str, granularity: str = 'MONTHLY') -> Dict:
        """Get AWS cost analysis"""
        try:
            response = self.ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date,
                    'End': end_date
                },
                Granularity=granularity,
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {'Type': 'DIMENSION', 'Key': 'SERVICE'}
                ]
            )
            
            cost_data = {
                'time_period': response['TimePeriod'],
                'total_cost': response['ResultsByTime'][0]['Total']['UnblendedCost']['Amount'],
                'currency': response['ResultsByTime'][0]['Total']['UnblendedCost']['Unit'],
                'services': []
            }
            
            for group in response['ResultsByTime'][0]['Groups']:
                service_info = {
                    'service': group['Keys'][0],
                    'cost': group['Metrics']['UnblendedCost']['Amount'],
                    'unit': group['Metrics']['UnblendedCost']['Unit']
                }
                cost_data['services'].append(service_info)
            
            self.logger.info(f"Cost analysis retrieved for {start_date} to {end_date}")
            return cost_data
            
        except Exception as e:
            self.logger.error(f"Error getting cost analysis: {e}")
            return {}
    
    # Security Group Management
    def list_security_groups(self) -> List[Dict]:
        """List security groups"""
        try:
            response = self.ec2_client.describe_security_groups()
            security_groups = []
            
            for sg in response['SecurityGroups']:
                sg_info = {
                    'id': sg['GroupId'],
                    'name': sg['GroupName'],
                    'description': sg['Description'],
                    'vpc_id': sg['VpcId'],
                    'inbound_rules': sg['IpPermissions'],
                    'outbound_rules': sg['IpPermissionsEgress']
                }
                security_groups.append(sg_info)
            
            self.logger.info(f"Found {len(security_groups)} security groups")
            return security_groups
            
        except Exception as e:
            self.logger.error(f"Error listing security groups: {e}")
            return []
    
    def create_security_group(self, name: str, description: str, vpc_id: str = None) -> Dict:
        """Create security group"""
        try:
            if not vpc_id:
                vpc_id = self.default_vpc_id
            
            response = self.ec2_client.create_security_group(
                GroupName=name,
                Description=description,
                VpcId=vpc_id
            )
            
            self.logger.info(f"Security group created: {response['GroupId']}")
            return {
                'group_id': response['GroupId'],
                'group_name': name,
                'description': description
            }
            
        except Exception as e:
            self.logger.error(f"Error creating security group {name}: {e}")
            return {}
    
    # CloudWatch Monitoring
    def get_metrics(self, namespace: str, metric_name: str, dimensions: List[Dict], 
                   start_time: datetime, end_time: datetime, period: int = 300) -> List[Dict]:
        """Get CloudWatch metrics"""
        try:
            response = self.cloudwatch_client.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=start_time,
                EndTime=end_time,
                Period=period,
                Statistics=['Average', 'Maximum', 'Minimum']
            )
            
            metrics = []
            for datapoint in response['Datapoints']:
                metric_info = {
                    'timestamp': datapoint['Timestamp'].isoformat(),
                    'average': datapoint.get('Average'),
                    'maximum': datapoint.get('Maximum'),
                    'minimum': datapoint.get('Minimum')
                }
                metrics.append(metric_info)
            
            self.logger.info(f"Retrieved {len(metrics)} metric datapoints")
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error getting metrics: {e}")
            return []
    
    def create_alarm(self, alarm_config: Dict) -> bool:
        """Create CloudWatch alarm"""
        try:
            self.cloudwatch_client.put_metric_alarm(
                AlarmName=alarm_config['name'],
                AlarmDescription=alarm_config.get('description', ''),
                MetricName=alarm_config['metric_name'],
                Namespace=alarm_config['namespace'],
                Dimensions=alarm_config['dimensions'],
                Period=alarm_config.get('period', 300),
                EvaluationPeriods=alarm_config.get('evaluation_periods', 1),
                Threshold=alarm_config['threshold'],
                ComparisonOperator=alarm_config['comparison_operator'],
                Statistic=alarm_config.get('statistic', 'Average')
            )
            
            self.logger.info(f"CloudWatch alarm created: {alarm_config['name']}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating CloudWatch alarm: {e}")
            return False
    
    def generate_report(self, report_type: str = 'summary') -> Dict:
        """Generate comprehensive AWS report"""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'region': self.default_region,
                'report_type': report_type
            }
            
            if report_type == 'summary' or report_type == 'ec2':
                report['ec2'] = {
                    'instances': self.list_instances(),
                    'security_groups': self.list_security_groups()
                }
            
            if report_type == 'summary' or report_type == 'storage':
                report['storage'] = {
                    'buckets': self.list_buckets()
                }
            
            if report_type == 'summary' or report_type == 'security':
                report['security'] = {
                    'users': self.list_users()
                }
            
            if report_type == 'summary' or report_type == 'serverless':
                report['serverless'] = {
                    'functions': self.list_functions()
                }
            
            if report_type == 'summary' or report_type == 'infrastructure':
                report['infrastructure'] = {
                    'stacks': self.list_stacks()
                }
            
            if report_type == 'cost':
                end_date = datetime.now()
                start_date = end_date - timedelta(days=30)
                report['cost'] = self.get_cost_analysis(
                    start_date.strftime('%Y-%m-%d'),
                    end_date.strftime('%Y-%m-%d')
                )
            
            self.logger.info(f"AWS report generated: {report_type}")
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            return {}


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='AWS Manager')
    parser.add_argument('--config', type=str, help='Configuration file path')
    parser.add_argument('--region', type=str, help='AWS region')
    parser.add_argument('--list-instances', action='store_true', help='List EC2 instances')
    parser.add_argument('--list-buckets', action='store_true', help='List S3 buckets')
    parser.add_argument('--list-users', action='store_true', help='List IAM users')
    parser.add_argument('--list-functions', action='store_true', help='List Lambda functions')
    parser.add_argument('--list-stacks', action='store_true', help='List CloudFormation stacks')
    parser.add_argument('--create-instance', type=str, help='Create EC2 instance (config file)')
    parser.add_argument('--start-instance', type=str, help='Start EC2 instance')
    parser.add_argument('--stop-instance', type=str, help='Stop EC2 instance')
    parser.add_argument('--terminate-instance', type=str, help='Terminate EC2 instance')
    parser.add_argument('--create-bucket', type=str, help='Create S3 bucket')
    parser.add_argument('--upload-file', nargs=3, help='Upload file to S3 (bucket, file, key)')
    parser.add_argument('--download-file', nargs=3, help='Download file from S3 (bucket, key, file)')
    parser.add_argument('--create-user', type=str, help='Create IAM user')
    parser.add_argument('--delete-user', type=str, help='Delete IAM user')
    parser.add_argument('--create-function', type=str, help='Create Lambda function (config file)')
    parser.add_argument('--delete-function', type=str, help='Delete Lambda function')
    parser.add_argument('--create-stack', nargs=2, help='Create CloudFormation stack (name, template)')
    parser.add_argument('--delete-stack', type=str, help='Delete CloudFormation stack')
    parser.add_argument('--cost-analysis', nargs=2, help='Get cost analysis (start_date, end_date)')
    parser.add_argument('--report', type=str, default='summary', help='Generate report (summary, ec2, storage, security, serverless, infrastructure, cost)')
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Override region if specified
    if args.region:
        config['default_region'] = args.region
    
    # Create AWS manager
    manager = AWSManager(config)
    
    # Handle different operations
    if args.list_instances:
        instances = manager.list_instances()
        print(json.dumps(instances, indent=2))
    
    elif args.list_buckets:
        buckets = manager.list_buckets()
        print(json.dumps(buckets, indent=2))
    
    elif args.list_users:
        users = manager.list_users()
        print(json.dumps(users, indent=2))
    
    elif args.list_functions:
        functions = manager.list_functions()
        print(json.dumps(functions, indent=2))
    
    elif args.list_stacks:
        stacks = manager.list_stacks()
        print(json.dumps(stacks, indent=2))
    
    elif args.create_instance:
        with open(args.create_instance, 'r') as f:
            instance_config = json.load(f)
        result = manager.create_instance(instance_config)
        print(json.dumps(result, indent=2))
    
    elif args.start_instance:
        success = manager.start_instance(args.start_instance)
        print(f"Start instance: {'success' if success else 'failed'}")
    
    elif args.stop_instance:
        success = manager.stop_instance(args.stop_instance)
        print(f"Stop instance: {'success' if success else 'failed'}")
    
    elif args.terminate_instance:
        success = manager.terminate_instance(args.terminate_instance)
        print(f"Terminate instance: {'success' if success else 'failed'}")
    
    elif args.create_bucket:
        success = manager.create_bucket(args.create_bucket)
        print(f"Create bucket: {'success' if success else 'failed'}")
    
    elif args.upload_file:
        bucket, file_path, key = args.upload_file
        success = manager.upload_file(bucket, file_path, key)
        print(f"Upload file: {'success' if success else 'failed'}")
    
    elif args.download_file:
        bucket, key, file_path = args.download_file
        success = manager.download_file(bucket, key, file_path)
        print(f"Download file: {'success' if success else 'failed'}")
    
    elif args.create_user:
        success = manager.create_user(args.create_user)
        print(f"Create user: {'success' if success else 'failed'}")
    
    elif args.delete_user:
        success = manager.delete_user(args.delete_user)
        print(f"Delete user: {'success' if success else 'failed'}")
    
    elif args.create_function:
        with open(args.create_function, 'r') as f:
            function_config = json.load(f)
        result = manager.create_function(function_config)
        print(json.dumps(result, indent=2))
    
    elif args.delete_function:
        success = manager.delete_function(args.delete_function)
        print(f"Delete function: {'success' if success else 'failed'}")
    
    elif args.create_stack:
        stack_name, template_url = args.create_stack
        result = manager.create_stack(stack_name, template_url)
        print(json.dumps(result, indent=2))
    
    elif args.delete_stack:
        success = manager.delete_stack(args.delete_stack)
        print(f"Delete stack: {'success' if success else 'failed'}")
    
    elif args.cost_analysis:
        start_date, end_date = args.cost_analysis
        cost_data = manager.get_cost_analysis(start_date, end_date)
        print(json.dumps(cost_data, indent=2))
    
    elif args.report:
        report = manager.generate_report(args.report)
        print(json.dumps(report, indent=2))
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main() 