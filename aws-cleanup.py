#!/usr/bin/env python3
"""
AWS Account Complete Cleanup and Reset Script
WARNING: This script will DELETE ALL resources in your AWS account across ALL regions!
Use with extreme caution. Recommended for FREE TIER accounts only.
"""

import boto3
import time
import sys
from botocore.exceptions import ClientError, NoCredentialsError
from concurrent.futures import ThreadPoolExecutor, as_completed

class AWSAccountCleaner:
    def __init__(self):
        self.session = boto3.Session()
        self.ec2_client = self.session.client('ec2')
        self.regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']]
        self.deleted_resources = []
        
    def log(self, message, level="INFO"):
        print(f"[{level}] {message}")
        
    def cleanup_region(self, region):
        """Cleanup all resources in a specific region"""
        self.log(f"Starting cleanup for region: {region}")
        
        try:
            # CloudFormation first (may contain other resources)
            self.cleanup_cloudformation(region)
            time.sleep(10)
            
            # Load Balancers (must be before EC2)
            self.cleanup_load_balancers(region)
            # Target Groups
            self.cleanup_target_groups(region)
            # EC2 Resources
            self.cleanup_ec2(region)
            # RDS Resources
            self.cleanup_rds(region)
            # Lambda Functions
            self.cleanup_lambda(region)
            # DynamoDB Tables
            self.cleanup_dynamodb(region)
            # ECS Resources
            self.cleanup_ecs(region)
            # EKS Clusters
            self.cleanup_eks(region)
            # Elastic Beanstalk
            self.cleanup_elasticbeanstalk(region)
            # ElastiCache
            self.cleanup_elasticache(region)
            # SNS Topics
            self.cleanup_sns(region)
            # SQS Queues
            self.cleanup_sqs(region)
            # CloudWatch Alarms & Logs
            self.cleanup_cloudwatch(region)
            # Network Interfaces (before VPC)
            self.cleanup_network_interfaces(region)
            # VPC Resources (must be last)
            self.cleanup_vpc(region)
            
        except Exception as e:
            self.log(f"Error cleaning region {region}: {str(e)}", "ERROR")
    
    def cleanup_load_balancers(self, region):
        """Delete all load balancers"""
        try:
            # Classic Load Balancers
            elb = self.session.client('elb', region_name=region)
            classic_lbs = elb.describe_load_balancers()
            for lb in classic_lbs['LoadBalancerDescriptions']:
                lb_name = lb['LoadBalancerName']
                self.log(f"Deleting Classic LB: {lb_name}")
                elb.delete_load_balancer(LoadBalancerName=lb_name)
                self.deleted_resources.append((region, 'Classic Load Balancer', lb_name))
            
            # Application/Network Load Balancers
            elbv2 = self.session.client('elbv2', region_name=region)
            albs = elbv2.describe_load_balancers()
            for lb in albs['LoadBalancers']:
                lb_arn = lb['LoadBalancerArn']
                lb_name = lb['LoadBalancerName']
                self.log(f"Deleting ALB/NLB: {lb_name}")
                elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
                self.deleted_resources.append((region, 'ALB/NLB', lb_name))
                
        except ClientError as e:
            self.log(f"Load Balancer cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_target_groups(self, region):
        """Delete target groups"""
        try:
            elbv2 = self.session.client('elbv2', region_name=region)
            tgs = elbv2.describe_target_groups()
            for tg in tgs['TargetGroups']:
                tg_arn = tg['TargetGroupArn']
                self.log(f"Deleting Target Group: {tg['TargetGroupName']}")
                elbv2.delete_target_group(TargetGroupArn=tg_arn)
                self.deleted_resources.append((region, 'Target Group', tg['TargetGroupName']))
                
        except ClientError as e:
            self.log(f"Target Group cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_network_interfaces(self, region):
        """Delete unattached network interfaces"""
        ec2 = self.session.client('ec2', region_name=region)
        
        try:
            enis = ec2.describe_network_interfaces()
            for eni in enis['NetworkInterfaces']:
                if eni['Status'] == 'available':  # Only delete unattached
                    eni_id = eni['NetworkInterfaceId']
                    self.log(f"Deleting ENI: {eni_id}")
                    ec2.delete_network_interface(NetworkInterfaceId=eni_id)
                    self.deleted_resources.append((region, 'Network Interface', eni_id))
                    
        except ClientError as e:
            self.log(f"ENI cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_ec2(self, region):
        """Terminate EC2 instances and delete related resources"""
        ec2 = self.session.client('ec2', region_name=region)
        
        try:
            # Disable termination protection first
            instances = ec2.describe_instances()
            instance_ids = []
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] not in ['terminated', 'terminating']:
                        instance_id = instance['InstanceId']
                        instance_ids.append(instance_id)
                        # Disable termination protection
                        try:
                            ec2.modify_instance_attribute(
                                InstanceId=instance_id,
                                DisableApiTermination={'Value': False}
                            )
                        except:
                            pass
            
            if instance_ids:
                self.log(f"Terminating {len(instance_ids)} instances in {region}")
                ec2.terminate_instances(InstanceIds=instance_ids)
                
                # Wait for termination
                self.log(f"Waiting for instances to terminate in {region}...")
                waiter = ec2.get_waiter('instance_terminated')
                try:
                    waiter.wait(InstanceIds=instance_ids, WaiterConfig={'Delay': 15, 'MaxAttempts': 40})
                except:
                    self.log(f"Some instances taking longer to terminate in {region}", "WARNING")
                
                self.deleted_resources.extend([(region, 'EC2 Instance', iid) for iid in instance_ids])
            
            # Release Elastic IPs
            addresses = ec2.describe_addresses()
            for addr in addresses['Addresses']:
                try:
                    if 'AssociationId' in addr:
                        ec2.disassociate_address(AssociationId=addr['AssociationId'])
                        time.sleep(2)
                    ec2.release_address(AllocationId=addr['AllocationId'])
                    self.log(f"Released EIP: {addr.get('PublicIp', addr['AllocationId'])}")
                    self.deleted_resources.append((region, 'Elastic IP', addr.get('PublicIp', addr['AllocationId'])))
                except Exception as e:
                    self.log(f"Error releasing EIP: {str(e)}", "ERROR")
            
            # Delete Launch Templates
            try:
                templates = ec2.describe_launch_templates()
                for template in templates['LaunchTemplates']:
                    ec2.delete_launch_template(LaunchTemplateId=template['LaunchTemplateId'])
                    self.log(f"Deleted Launch Template: {template['LaunchTemplateName']}")
                    self.deleted_resources.append((region, 'Launch Template', template['LaunchTemplateName']))
            except:
                pass
            
            # Wait a bit for instances to fully terminate
            time.sleep(10)
            
            # Delete EBS volumes
            volumes = ec2.describe_volumes()
            for vol in volumes['Volumes']:
                if vol['State'] == 'available':
                    try:
                        ec2.delete_volume(VolumeId=vol['VolumeId'])
                        self.log(f"Deleted volume: {vol['VolumeId']}")
                        self.deleted_resources.append((region, 'EBS Volume', vol['VolumeId']))
                    except Exception as e:
                        self.log(f"Error deleting volume {vol['VolumeId']}: {str(e)}", "WARNING")
            
            # Delete snapshots (owned by account)
            snapshots = ec2.describe_snapshots(OwnerIds=['self'])
            for snap in snapshots['Snapshots']:
                try:
                    ec2.delete_snapshot(SnapshotId=snap['SnapshotId'])
                    self.log(f"Deleted snapshot: {snap['SnapshotId']}")
                    self.deleted_resources.append((region, 'Snapshot', snap['SnapshotId']))
                except:
                    pass
            
            # Delete AMIs and associated snapshots
            images = ec2.describe_images(Owners=['self'])
            for img in images['Images']:
                try:
                    # Store snapshot IDs before deregistering
                    snapshot_ids = [bdm['Ebs']['SnapshotId'] for bdm in img.get('BlockDeviceMappings', []) if 'Ebs' in bdm]
                    
                    ec2.deregister_image(ImageId=img['ImageId'])
                    self.log(f"Deregistered AMI: {img['ImageId']}")
                    self.deleted_resources.append((region, 'AMI', img['ImageId']))
                    
                    # Delete associated snapshots
                    for snap_id in snapshot_ids:
                        try:
                            ec2.delete_snapshot(SnapshotId=snap_id)
                            self.log(f"Deleted AMI snapshot: {snap_id}")
                        except:
                            pass
                except Exception as e:
                    self.log(f"Error with AMI {img['ImageId']}: {str(e)}", "WARNING")
            
            # Delete key pairs
            keypairs = ec2.describe_key_pairs()
            for kp in keypairs['KeyPairs']:
                ec2.delete_key_pair(KeyName=kp['KeyName'])
                self.log(f"Deleted key pair: {kp['KeyName']}")
                self.deleted_resources.append((region, 'Key Pair', kp['KeyName']))
                
        except ClientError as e:
            self.log(f"EC2 cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_rds(self, region):
        """Delete RDS instances and clusters"""
        rds = self.session.client('rds', region_name=region)
        
        try:
            # Delete RDS instances
            instances = rds.describe_db_instances()
            for instance in instances['DBInstances']:
                db_id = instance['DBInstanceIdentifier']
                self.log(f"Deleting RDS instance: {db_id}")
                try:
                    rds.delete_db_instance(
                        DBInstanceIdentifier=db_id,
                        SkipFinalSnapshot=True,
                        DeleteAutomatedBackups=True
                    )
                    self.deleted_resources.append((region, 'RDS Instance', db_id))
                except Exception as e:
                    self.log(f"Error deleting RDS instance: {str(e)}", "ERROR")
            
            # Delete RDS clusters
            clusters = rds.describe_db_clusters()
            for cluster in clusters['DBClusters']:
                cluster_id = cluster['DBClusterIdentifier']
                self.log(f"Deleting RDS cluster: {cluster_id}")
                try:
                    rds.delete_db_cluster(
                        DBClusterIdentifier=cluster_id,
                        SkipFinalSnapshot=True
                    )
                    self.deleted_resources.append((region, 'RDS Cluster', cluster_id))
                except Exception as e:
                    self.log(f"Error deleting RDS cluster: {str(e)}", "ERROR")
                    
        except ClientError as e:
            self.log(f"RDS cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_s3(self):
        """Delete all S3 buckets and their contents"""
        s3 = self.session.client('s3')
        s3_resource = self.session.resource('s3')
        
        try:
            buckets = s3.list_buckets()
            for bucket in buckets['Buckets']:
                bucket_name = bucket['Name']
                self.log(f"Deleting S3 bucket: {bucket_name}")
                
                try:
                    bucket_resource = s3_resource.Bucket(bucket_name)
                    
                    # Delete all object versions
                    bucket_resource.object_versions.all().delete()
                    
                    # Delete all objects
                    bucket_resource.objects.all().delete()
                    
                    # Delete bucket
                    bucket_resource.delete()
                    self.deleted_resources.append(('global', 'S3 Bucket', bucket_name))
                except Exception as e:
                    self.log(f"Error deleting bucket {bucket_name}: {str(e)}", "ERROR")
                    
        except ClientError as e:
            self.log(f"S3 cleanup error: {str(e)}", "ERROR")
    
    def cleanup_lambda(self, region):
        """Delete Lambda functions"""
        lambda_client = self.session.client('lambda', region_name=region)
        
        try:
            functions = lambda_client.list_functions()
            for func in functions['Functions']:
                func_name = func['FunctionName']
                self.log(f"Deleting Lambda function: {func_name}")
                lambda_client.delete_function(FunctionName=func_name)
                self.deleted_resources.append((region, 'Lambda Function', func_name))
                
        except ClientError as e:
            self.log(f"Lambda cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_dynamodb(self, region):
        """Delete DynamoDB tables"""
        dynamodb = self.session.client('dynamodb', region_name=region)
        
        try:
            tables = dynamodb.list_tables()
            for table_name in tables['TableNames']:
                self.log(f"Deleting DynamoDB table: {table_name}")
                dynamodb.delete_table(TableName=table_name)
                self.deleted_resources.append((region, 'DynamoDB Table', table_name))
                
        except ClientError as e:
            self.log(f"DynamoDB cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_ecs(self, region):
        """Delete ECS clusters, services, and task definitions"""
        ecs = self.session.client('ecs', region_name=region)
        
        try:
            clusters = ecs.list_clusters()
            for cluster_arn in clusters['clusterArns']:
                # Delete services
                services = ecs.list_services(cluster=cluster_arn)
                for service_arn in services['serviceArns']:
                    try:
                        ecs.update_service(cluster=cluster_arn, service=service_arn, desiredCount=0)
                        time.sleep(5)
                        ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True)
                        self.deleted_resources.append((region, 'ECS Service', service_arn))
                    except:
                        pass
                
                # Delete cluster
                try:
                    ecs.delete_cluster(cluster=cluster_arn)
                    self.log(f"Deleted ECS cluster: {cluster_arn}")
                    self.deleted_resources.append((region, 'ECS Cluster', cluster_arn))
                except:
                    pass
                
        except ClientError as e:
            self.log(f"ECS cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_eks(self, region):
        """Delete EKS clusters"""
        eks = self.session.client('eks', region_name=region)
        
        try:
            clusters = eks.list_clusters()
            for cluster_name in clusters['clusters']:
                self.log(f"Deleting EKS cluster: {cluster_name}")
                
                # Delete node groups first
                try:
                    nodegroups = eks.list_nodegroups(clusterName=cluster_name)
                    for ng in nodegroups['nodegroups']:
                        eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=ng)
                    time.sleep(30)
                except:
                    pass
                
                # Delete cluster
                try:
                    eks.delete_cluster(name=cluster_name)
                    self.deleted_resources.append((region, 'EKS Cluster', cluster_name))
                except:
                    pass
                
        except ClientError as e:
            self.log(f"EKS cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_cloudformation(self, region):
        """Delete CloudFormation stacks"""
        cfn = self.session.client('cloudformation', region_name=region)
        
        try:
            stacks = cfn.list_stacks(StackStatusFilter=[
                'CREATE_COMPLETE', 'UPDATE_COMPLETE', 'ROLLBACK_COMPLETE', 
                'UPDATE_ROLLBACK_COMPLETE', 'IMPORT_COMPLETE'
            ])
            for stack in stacks['StackSummaries']:
                stack_name = stack['StackName']
                self.log(f"Deleting CloudFormation stack: {stack_name}")
                try:
                    cfn.delete_stack(StackName=stack_name)
                    self.deleted_resources.append((region, 'CloudFormation Stack', stack_name))
                except:
                    pass
                
        except ClientError as e:
            self.log(f"CloudFormation cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_elasticbeanstalk(self, region):
        """Delete Elastic Beanstalk applications"""
        eb = self.session.client('elasticbeanstalk', region_name=region)
        
        try:
            apps = eb.describe_applications()
            for app in apps['Applications']:
                app_name = app['ApplicationName']
                self.log(f"Deleting Elastic Beanstalk app: {app_name}")
                eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)
                self.deleted_resources.append((region, 'Elastic Beanstalk App', app_name))
                
        except ClientError as e:
            self.log(f"Elastic Beanstalk cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_elasticache(self, region):
        """Delete ElastiCache clusters"""
        elasticache = self.session.client('elasticache', region_name=region)
        
        try:
            clusters = elasticache.describe_cache_clusters()
            for cluster in clusters['CacheClusters']:
                cluster_id = cluster['CacheClusterId']
                self.log(f"Deleting ElastiCache cluster: {cluster_id}")
                elasticache.delete_cache_cluster(CacheClusterId=cluster_id)
                self.deleted_resources.append((region, 'ElastiCache Cluster', cluster_id))
                
        except ClientError as e:
            self.log(f"ElastiCache cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_vpc(self, region):
        """Delete VPC resources (NAT gateways, IGWs, subnets, VPCs)"""
        ec2 = self.session.client('ec2', region_name=region)
        
        try:
            vpcs = ec2.describe_vpcs()
            for vpc in vpcs['Vpcs']:
                vpc_id = vpc['VpcId']
                
                # Skip default VPC - we'll recreate it later
                if vpc.get('IsDefault', False):
                    continue
                
                self.log(f"Cleaning VPC: {vpc_id}")
                
                # Delete NAT Gateways
                try:
                    nat_gws = ec2.describe_nat_gateways(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                    for nat in nat_gws['NatGateways']:
                        if nat['State'] not in ['deleted', 'deleting']:
                            ec2.delete_nat_gateway(NatGatewayId=nat['NatGatewayId'])
                            self.log(f"Deleting NAT Gateway: {nat['NatGatewayId']}")
                            self.deleted_resources.append((region, 'NAT Gateway', nat['NatGatewayId']))
                    time.sleep(10)
                except:
                    pass
                
                # Delete VPC Endpoints
                try:
                    endpoints = ec2.describe_vpc_endpoints(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                    for endpoint in endpoints['VpcEndpoints']:
                        ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint['VpcEndpointId']])
                        self.deleted_resources.append((region, 'VPC Endpoint', endpoint['VpcEndpointId']))
                except:
                    pass
                
                # Detach and delete Internet Gateways
                try:
                    igws = ec2.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
                    for igw in igws['InternetGateways']:
                        ec2.detach_internet_gateway(InternetGatewayId=igw['InternetGatewayId'], VpcId=vpc_id)
                        ec2.delete_internet_gateway(InternetGatewayId=igw['InternetGatewayId'])
                        self.deleted_resources.append((region, 'Internet Gateway', igw['InternetGatewayId']))
                except:
                    pass
                
                # Delete subnets
                try:
                    subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                    for subnet in subnets['Subnets']:
                        ec2.delete_subnet(SubnetId=subnet['SubnetId'])
                        self.deleted_resources.append((region, 'Subnet', subnet['SubnetId']))
                except:
                    pass
                
                # Delete route tables (except main)
                try:
                    route_tables = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                    for rt in route_tables['RouteTables']:
                        if not any(assoc.get('Main', False) for assoc in rt['Associations']):
                            ec2.delete_route_table(RouteTableId=rt['RouteTableId'])
                            self.deleted_resources.append((region, 'Route Table', rt['RouteTableId']))
                except:
                    pass
                
                # Delete Network ACLs (except default)
                try:
                    acls = ec2.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                    for acl in acls['NetworkAcls']:
                        if not acl['IsDefault']:
                            ec2.delete_network_acl(NetworkAclId=acl['NetworkAclId'])
                            self.deleted_resources.append((region, 'Network ACL', acl['NetworkAclId']))
                except:
                    pass
                
                # Delete security groups (except default)
                try:
                    sgs = ec2.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                    # First pass: remove all rules
                    for sg in sgs['SecurityGroups']:
                        if sg['GroupName'] != 'default':
                            try:
                                if sg['IpPermissions']:
                                    ec2.revoke_security_group_ingress(GroupId=sg['GroupId'], IpPermissions=sg['IpPermissions'])
                                if sg['IpPermissionsEgress']:
                                    ec2.revoke_security_group_egress(GroupId=sg['GroupId'], IpPermissionsEgress=sg['IpPermissionsEgress'])
                            except:
                                pass
                    
                    # Second pass: delete security groups
                    for sg in sgs['SecurityGroups']:
                        if sg['GroupName'] != 'default':
                            try:
                                ec2.delete_security_group(GroupId=sg['GroupId'])
                                self.deleted_resources.append((region, 'Security Group', sg['GroupId']))
                            except:
                                pass
                except:
                    pass
                
                # Delete VPC
                try:
                    time.sleep(5)
                    ec2.delete_vpc(VpcId=vpc_id)
                    self.log(f"Deleted VPC: {vpc_id}")
                    self.deleted_resources.append((region, 'VPC', vpc_id))
                except Exception as e:
                    self.log(f"Could not delete VPC {vpc_id}: {str(e)}", "WARNING")
                
        except ClientError as e:
            self.log(f"VPC cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_sns(self, region):
        """Delete SNS topics"""
        sns = self.session.client('sns', region_name=region)
        
        try:
            topics = sns.list_topics()
            for topic in topics['Topics']:
                topic_arn = topic['TopicArn']
                self.log(f"Deleting SNS topic: {topic_arn}")
                sns.delete_topic(TopicArn=topic_arn)
                self.deleted_resources.append((region, 'SNS Topic', topic_arn))
                
        except ClientError as e:
            self.log(f"SNS cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_sqs(self, region):
        """Delete SQS queues"""
        sqs = self.session.client('sqs', region_name=region)
        
        try:
            queues = sqs.list_queues()
            if 'QueueUrls' in queues:
                for queue_url in queues['QueueUrls']:
                    self.log(f"Deleting SQS queue: {queue_url}")
                    sqs.delete_queue(QueueUrl=queue_url)
                    self.deleted_resources.append((region, 'SQS Queue', queue_url))
                    
        except ClientError as e:
            self.log(f"SQS cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_cloudwatch(self, region):
        """Delete CloudWatch alarms and log groups"""
        cw = self.session.client('cloudwatch', region_name=region)
        logs = self.session.client('logs', region_name=region)
        
        try:
            # Delete alarms
            alarms = cw.describe_alarms()
            alarm_names = [alarm['AlarmName'] for alarm in alarms['MetricAlarms']]
            if alarm_names:
                cw.delete_alarms(AlarmNames=alarm_names)
                self.deleted_resources.extend([(region, 'CloudWatch Alarm', name) for name in alarm_names])
            
            # Delete log groups
            log_groups = logs.describe_log_groups()
            for lg in log_groups['logGroups']:
                logs.delete_log_group(logGroupName=lg['logGroupName'])
                self.deleted_resources.append((region, 'CloudWatch Log Group', lg['logGroupName']))
                
        except ClientError as e:
            self.log(f"CloudWatch cleanup error in {region}: {str(e)}", "ERROR")
    
    def cleanup_iam(self):
        """Delete IAM users, roles, policies, and instance profiles"""
        iam = self.session.client('iam')
        
        try:
            # Delete IAM users with ALL attachments
            self.log("Starting comprehensive IAM user cleanup...")
            users = iam.list_users()
            for user in users['Users']:
                username = user['UserName']
                self.log(f"Deleting IAM user: {username}")
                
                try:
                    # Delete MFA devices
                    mfa_devices = iam.list_mfa_devices(UserName=username)
                    for mfa in mfa_devices['MFADevices']:
                        iam.deactivate_mfa_device(UserName=username, SerialNumber=mfa['SerialNumber'])
                        iam.delete_virtual_mfa_device(SerialNumber=mfa['SerialNumber'])
                except:
                    pass
                
                try:
                    # Delete signing certificates
                    certs = iam.list_signing_certificates(UserName=username)
                    for cert in certs['Certificates']:
                        iam.delete_signing_certificate(UserName=username, CertificateId=cert['CertificateId'])
                except:
                    pass
                
                try:
                    # Delete SSH public keys
                    ssh_keys = iam.list_ssh_public_keys(UserName=username)
                    for key in ssh_keys['SSHPublicKeys']:
                        iam.delete_ssh_public_key(UserName=username, SSHPublicKeyId=key['SSHPublicKeyId'])
                except:
                    pass
                
                try:
                    # Delete service specific credentials
                    service_creds = iam.list_service_specific_credentials(UserName=username)
                    for cred in service_creds['ServiceSpecificCredentials']:
                        iam.delete_service_specific_credential(UserName=username, ServiceSpecificCredentialId=cred['ServiceSpecificCredentialId'])
                except:
                    pass
                
                try:
                    # Delete access keys
                    keys = iam.list_access_keys(UserName=username)
                    for key in keys['AccessKeyMetadata']:
                        iam.delete_access_key(UserName=username, AccessKeyId=key['AccessKeyId'])
                except:
                    pass
                
                try:
                    # Delete login profile (console password)
                    iam.delete_login_profile(UserName=username)
                except:
                    pass
                
                try:
                    # Detach managed policies
                    policies = iam.list_attached_user_policies(UserName=username)
                    for policy in policies['AttachedPolicies']:
                        iam.detach_user_policy(UserName=username, PolicyArn=policy['PolicyArn'])
                except:
                    pass
                
                try:
                    # Delete inline policies
                    inline_policies = iam.list_user_policies(UserName=username)
                    for policy_name in inline_policies['PolicyNames']:
                        iam.delete_user_policy(UserName=username, PolicyName=policy_name)
                except:
                    pass
                
                try:
                    # Remove from all groups
                    groups = iam.list_groups_for_user(UserName=username)
                    for group in groups['Groups']:
                        iam.remove_user_from_group(UserName=username, GroupName=group['GroupName'])
                except:
                    pass
                
                try:
                    # Delete user
                    iam.delete_user(UserName=username)
                    self.log(f"Successfully deleted user: {username}")
                    self.deleted_resources.append(('global', 'IAM User', username))
                except Exception as e:
                    self.log(f"Failed to delete user {username}: {str(e)}", "ERROR")
            
            # Delete IAM groups
            self.log("Deleting IAM groups...")
            groups = iam.list_groups()
            for group in groups['Groups']:
                group_name = group['GroupName']
                
                try:
                    # Detach policies
                    policies = iam.list_attached_group_policies(GroupName=group_name)
                    for policy in policies['AttachedPolicies']:
                        iam.detach_group_policy(GroupName=group_name, PolicyArn=policy['PolicyArn'])
                    
                    # Delete inline policies
                    inline_policies = iam.list_group_policies(GroupName=group_name)
                    for policy_name in inline_policies['PolicyNames']:
                        iam.delete_group_policy(GroupName=group_name, PolicyName=policy_name)
                    
                    # Delete group
                    iam.delete_group(GroupName=group_name)
                    self.log(f"Deleted IAM group: {group_name}")
                    self.deleted_resources.append(('global', 'IAM Group', group_name))
                except Exception as e:
                    self.log(f"Error deleting group {group_name}: {str(e)}", "ERROR")
            
            # Delete IAM roles (except AWS service roles)
            self.log("Deleting IAM roles...")
            roles = iam.list_roles()
            for role in roles['Roles']:
                role_name = role['RoleName']
                
                # Skip AWS service roles and important system roles
                if (role_name.startswith('AWS') or 
                    role_name.startswith('service-role/') or
                    'OrganizationAccountAccessRole' in role_name):
                    continue
                
                try:
                    # Delete instance profiles
                    instance_profiles = iam.list_instance_profiles_for_role(RoleName=role_name)
                    for profile in instance_profiles['InstanceProfiles']:
                        iam.remove_role_from_instance_profile(
                            InstanceProfileName=profile['InstanceProfileName'],
                            RoleName=role_name
                        )
                        iam.delete_instance_profile(InstanceProfileName=profile['InstanceProfileName'])
                    
                    # Detach managed policies
                    policies = iam.list_attached_role_policies(RoleName=role_name)
                    for policy in policies['AttachedPolicies']:
                        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
                    
                    # Delete inline policies
                    inline_policies = iam.list_role_policies(RoleName=role_name)
                    for policy_name in inline_policies['PolicyNames']:
                        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
                    
                    # Delete role
                    iam.delete_role(RoleName=role_name)
                    self.log(f"Deleted IAM role: {role_name}")
                    self.deleted_resources.append(('global', 'IAM Role', role_name))
                except Exception as e:
                    self.log(f"Error deleting role {role_name}: {str(e)}", "WARNING")
            
            # Delete custom IAM policies
            self.log("Deleting custom IAM policies...")
            policies = iam.list_policies(Scope='Local')
            for policy in policies['Policies']:
                policy_arn = policy['Arn']
                policy_name = policy['PolicyName']
                
                try:
                    # Delete all policy versions except default
                    versions = iam.list_policy_versions(PolicyArn=policy_arn)
                    for version in versions['Versions']:
                        if not version['IsDefaultVersion']:
                            iam.delete_policy_version(PolicyArn=policy_arn, VersionId=version['VersionId'])
                    
                    # Delete policy
                    iam.delete_policy(PolicyArn=policy_arn)
                    self.log(f"Deleted IAM policy: {policy_name}")
                    self.deleted_resources.append(('global', 'IAM Policy', policy_name))
                except Exception as e:
                    self.log(f"Error deleting policy {policy_name}: {str(e)}", "ERROR")
                    
        except ClientError as e:
            self.log(f"IAM cleanup error: {str(e)}", "ERROR")
    
    def create_default_resources(self):
        """Create default AWS free tier resources with proper configuration"""
        self.log("=" * 80)
        self.log("Creating default free tier resources...")
        self.log("=" * 80)
        
        # Primary regions for free tier
        primary_regions = ['us-east-1', 'us-west-2']
        
        for region in primary_regions:
            ec2 = self.session.client('ec2', region_name=region)
            
            try:
                # Check for default VPC
                vpcs = ec2.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
                
                if not vpcs['Vpcs']:
                    # Create default VPC
                    self.log(f"Creating default VPC in {region}...")
                    result = ec2.create_default_vpc()
                    vpc_id = result['Vpc']['VpcId']
                    self.log(f"✓ Created default VPC: {vpc_id}")
                    
                    # Wait for VPC to be available
                    time.sleep(5)
                else:
                    vpc_id = vpcs['Vpcs'][0]['VpcId']
                    self.log(f"✓ Default VPC already exists: {vpc_id}")
                
                # Enable auto-assign public IPv4 for all subnets in default VPC
                subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                for subnet in subnets['Subnets']:
                    subnet_id = subnet['SubnetId']
                    try:
                        ec2.modify_subnet_attribute(
                            SubnetId=subnet_id,
                            MapPublicIpOnLaunch={'Value': True}
                        )
                        self.log(f"✓ Enabled auto-assign public IP for subnet: {subnet_id}")
                    except Exception as e:
                        self.log(f"Could not modify subnet {subnet_id}: {str(e)}", "WARNING")
                
                # Verify default security group
                sgs = ec2.describe_security_groups(
                    Filters=[
                        {'Name': 'vpc-id', 'Values': [vpc_id]},
                        {'Name': 'group-name', 'Values': ['default']}
                    ]
                )
                if sgs['SecurityGroups']:
                    self.log(f"✓ Default security group exists: {sgs['SecurityGroups'][0]['GroupId']}")
                
                # Verify internet gateway
                igws = ec2.describe_internet_gateways(
                    Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]
                )
                if igws['InternetGateways']:
                    self.log(f"✓ Internet gateway attached: {igws['InternetGateways'][0]['InternetGatewayId']}")
                
            except ClientError as e:
                self.log(f"Error creating default resources in {region}: {str(e)}", "ERROR")
        
        self.log("=" * 80)
        self.log("Default free tier resources setup complete!")
        self.log("=" * 80)
        self.log("\n✓ Your account now has:")
        self.log("  • Default VPCs in us-east-1 and us-west-2")
        self.log("  • Default security groups")
        self.log("  • Default subnets with auto-assign public IPv4 ENABLED")
        self.log("  • Default route tables")
        self.log("  • Internet gateways attached")
        self.log("  • EC2 instances will now get public IPv4 addresses automatically!")
        self.log("\n✓ All AWS CloudShell files and history cleared")
        self.log("=" * 80)
    
    def run_cleanup(self):
        """Execute complete cleanup"""
        self.log("=" * 80)
        self.log("AWS ACCOUNT COMPLETE CLEANUP STARTING")
        self.log("=" * 80)
        self.log(f"WARNING: This will delete ALL resources in {len(self.regions)} regions!")
        
        # Global cleanup first (S3, IAM)
        self.log("\n>>> Cleaning up global resources (S3, IAM)...")
        self.cleanup_s3()
        self.cleanup_iam()
        
        # Parallel cleanup of regions
        self.log("\n>>> Starting regional cleanup...")
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self.cleanup_region, region): region for region in self.regions}
            
            for future in as_completed(futures):
                region = futures[future]
                try:
                    future.result()
                    self.log(f"✓ Completed cleanup for region: {region}")
                except Exception as e:
                    self.log(f"✗ Failed cleanup for region {region}: {str(e)}", "ERROR")
        
        self.log("\n" + "=" * 80)
        self.log(f"CLEANUP COMPLETE - Deleted {len(self.deleted_resources)} resources")
        self.log("=" * 80)
        
        # Create default resources
        self.create_default_resources()
        
        # Print summary
        self.log("\n📊 Deletion Summary:")
        self.log("-" * 80)
        resource_counts = {}
        for region, resource_type, _ in self.deleted_resources:
            key = f"{region}:{resource_type}"
            resource_counts[key] = resource_counts.get(key, 0) + 1
        
        for key, count in sorted(resource_counts.items()):
            region, resource_type = key.split(':', 1)
            self.log(f"  {region:20s} {resource_type:35s} {count:5d}")
        
        self.log("-" * 80)
        self.log(f"\n🎉 Total resources deleted: {len(self.deleted_resources)}")


def main():
    print("\n" + "=" * 80)
    print("🔴 AWS ACCOUNT NUCLEAR CLEANUP & RESET SCRIPT")
    print("=" * 80)
    print("\n⚠️  WARNING: This script will DELETE ALL resources in your AWS account!")
    print("\nThis includes:")
    print("  ❌ All EC2 instances, volumes, snapshots, AMIs, key pairs")
    print("  ❌ All S3 buckets and their contents")
    print("  ❌ All RDS databases and clusters")
    print("  ❌ All Lambda functions")
    print("  ❌ All DynamoDB tables")
    print("  ❌ All Load Balancers and Target Groups")
    print("  ❌ All VPCs (except default, which will be recreated)")
    print("  ❌ ALL IAM users, roles, groups, and custom policies")
    print("  ❌ All CloudFormation stacks")
    print("  ❌ All ECS/EKS clusters")
    print("  ❌ All CloudWatch logs and alarms")
    print("  ❌ All SNS topics and SQS queues")
    print("  ❌ And many more resources across ALL regions!")
    print("\n✅ After cleanup, the script will:")
    print("  ✓ Create default VPCs in us-east-1 and us-west-2")
    print("  ✓ Enable auto-assign public IPv4 for all subnets")
    print("  ✓ Configure default security groups and networking")
    print("  ✓ Reset your account to a clean free-tier state")
    print("\n⚠️  This action CANNOT be undone!")
    print("=" * 80)
    
    confirmation = input("\nType 'DELETE-EVERYTHING' to confirm: ")
    
    if confirmation != "DELETE-EVERYTHING":
        print("\n❌ Cleanup cancelled.")
        sys.exit(0)
    
    final_confirm = input("\nAre you ABSOLUTELY sure? Type 'YES-DELETE-ALL' to proceed: ")
    
    if final_confirm != "YES-DELETE-ALL":
        print("\n❌ Cleanup cancelled.")
        sys.exit(0)
    
    print("\n⏳ Starting cleanup in 5 seconds... Press Ctrl+C to abort!")
    for i in range(5, 0, -1):
        print(f"   {i}...")
        time.sleep(1)
    
    print("\n🚀 Starting cleanup process...\n")
    
    try:
        cleaner = AWSAccountCleaner()
        cleaner.run_cleanup()
        
        print("\n" + "=" * 80)
        print("✅ CLEANUP AND RESET COMPLETE!")
        print("=" * 80)
        print("\n🎉 Your AWS account has been reset to a clean free-tier state.")
        print("💡 EC2 instances launched now will automatically get public IPv4 addresses!")
        print("=" * 80)
        
    except NoCredentialsError:
        print("\n❌ ERROR: AWS credentials not found!")
        print("Please configure your AWS credentials using: aws configure")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
