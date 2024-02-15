#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from constructs import Construct
from aws_cdk import (
    CfnOutput,
    Stack,
    Duration,
    RemovalPolicy,
    aws_s3 as s3,
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_rds as rds,
    aws_iam as iam,
    aws_ecs_patterns as ecs_patterns
)
import cfg

class MirthConnectStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Creating a VPC for Mirth connect app to deploy
        vpc = ec2.Vpc(
            scope=self,
            id=cfg.NAME_PREFIX+'-vpc',
            max_azs=3,
            ip_addresses = ec2.IpAddresses.cidr(cfg.VPC_CIDR),
            subnet_configuration=[
                # modify here to change the types of subnets provisioned as part of the VPC
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PUBLIC, 
                    name=cfg.NAME_PREFIX + "-Public", 
                    map_public_ip_on_launch=False,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    name= cfg.NAME_PREFIX + "-PrivateWithEgress",
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    name= cfg.NAME_PREFIX + "-PrivateIsolated",
                    cidr_mask=24,
                ),
                
            ],
            nat_gateway_provider=ec2.NatProvider.gateway(),
            nat_gateways=1,  # Only provision 1 NAT GW - default is one per one per AZ
        )
  
        # VPC Endpoint for S3 (Gateway)
        #s3_gw_vpce = vpc.add_gateway_endpoint("s3GwVpce",service=ec2.GatewayVpcEndpointAwsService.S3)
        s3_gw_vpce = ec2.GatewayVpcEndpoint(
            scope=self, 
            id='s3GwVpce',
            service=ec2.GatewayVpcEndpointAwsService.S3,
            vpc=vpc,
            # optionally limit which subnets will have routes to the endpoint:
            #subnets=[ec2.SubnetSelection(
            #    subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT
            #)]
        )

        # print the arn for this VPC
        CfnOutput(self, "VPC", value=vpc.vpc_arn)

        db_instance = rds.DatabaseInstance(
            self, "mirth-database-instance",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_15_3
            ),
            # Optional: Adjust the instance type as needed for your use case
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
            credentials=rds.Credentials.from_generated_secret(cfg.DEFAULT_DATABASE_ADMIN_USER),  # Defaults to 'admin' username and generated password
            database_name=cfg.DEFAULT_DATABASE_NAME,
            removal_policy=RemovalPolicy.SNAPSHOT,  
            storage_encrypted=True,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
            vpc=vpc,
        )
  
        # print the db cluster identifier
        # CfnOutput(self, "DB Cluster", value=dbcluster.cluster_identifier)
        # CfnOutput(self, "DB Writer Endpoint", value=dbcluster.cluster_endpoint.hostname)
        # CfnOutput(self, "DB Reader Endpoint", value=dbcluster.cluster_read_endpoint.hostname)
        CfnOutput(self, "DB Password Secret ARN", value=db_instance.secret.secret_arn)
        
        # create ECS cluster
        cluster = ecs.Cluster(
            scope=self,
            id= cfg.NAME_PREFIX + '-ecs-cluster',
            vpc=vpc,
            # optionally turn on Container Insights :
            #container_insights=True,
        )
        
        # prepare the list of container ports as per configuration
        container_ports = [cfg.MIRTH_ADMIN_PORT]
        listeners = [ecs_patterns.NetworkListenerProps(name="mirthadmin",port=cfg.MIRTH_ADMIN_PORT)]
        target_groups = [ecs_patterns.NetworkTargetProps(listener="mirthadmin",container_port=cfg.MIRTH_ADMIN_PORT)]
        
        for port in cfg.ALLOWED_CHANNEL_PORTS_AND_PEERS.keys() :
            container_ports.append(port)
            listeners.append(ecs_patterns.NetworkListenerProps(name=str(port),port=port))
            target_groups.append(ecs_patterns.NetworkTargetProps(listener=str(port),container_port=port))

        # Fargate Task Properties
        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_ecs/ContainerImage.html
        task_image_props = ecs_patterns.NetworkLoadBalancedTaskImageProps(
            image=ecs.ContainerImage.from_registry(cfg.REGISTRY_IMAGE),
            container_name="mirthconnect",
            container_ports=container_ports,
            secrets={
                "DATABASE_PASSWORD": ecs.Secret.from_secrets_manager(db_instance.secret, field="password")
            },
            environment={
                "MIRTH_ADMIN_PORT": str(cfg.MIRTH_ADMIN_PORT),
                "DATABASE": 'postgres',
                # Use the instance endpoint's address and port for the DATABASE_URL
                "DATABASE_URL": f'jdbc:postgresql://{db_instance.instance_endpoint.hostname}:{db_instance.instance_endpoint.port}/{cfg.DEFAULT_DATABASE_NAME}',
                "DATABASE_USERNAME": cfg.DEFAULT_DATABASE_ADMIN_USER,
                "DATABASE_MAX_RETRY": str(2),
                "DATABASE_RETRY_WAIT": str(10000) 
            }
        )

        
        # S3 bucket for Logging
        log_bucket = s3.Bucket(
            scope=self,
            id=cfg.NAME_PREFIX + '-log-bucket',
            encryption=s3.BucketEncryption.S3_MANAGED,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            # optionally turn on versioning:
            #versioned=True,
        )

        # Fargate Service
        fargate_service = ecs_patterns.NetworkMultipleTargetGroupsFargateService(
            scope=self,
            id= cfg.NAME_PREFIX + '-fargate',
            cluster=cluster,
            cpu=cfg.TASK_CPU,
            memory_limit_mib=cfg.TASK_MEMORY_MIB,
            desired_count=cfg.TASK_COUNT,
            task_image_options=task_image_props,
            # enable below to be able to exec ssh to the Fargate container
            enable_execute_command=cfg.TASK_ENABLE_EXEC_COMMAND,
            load_balancers=[ecs_patterns.NetworkLoadBalancerProps(
                name=cfg.NAME_PREFIX + "NLB",
                public_load_balancer=cfg.PUBLIC_LOAD_BALANCER,
                listeners=listeners 
                )
            ],
            target_groups=target_groups
        )
  
        CfnOutput(self, "TaskExecRoleARN", value=fargate_service.task_definition.task_role.role_arn)

        # configure access logging for the load balancer
        # add additional listeners and target groups to the load balancer, as per the channel port configuration
        for lb in fargate_service.load_balancers:
            lb.log_access_logs(log_bucket, prefix="NLB-Access-Logs")

        # Set max tasks value for Autoscaling
        fargate_scaling_group = fargate_service.service.auto_scale_task_count(
            max_capacity=cfg.AUTOSCALE_MAX_TASKS
        )
        
        # Autoscaling policy for the fargate service - CPU utilization
        fargate_scaling_group.scale_on_cpu_utilization(
            "CpuScaling",
            target_utilization_percent=50,
            scale_in_cooldown=Duration.seconds(60),
            scale_out_cooldown=Duration.seconds(60),
        )

        # Enable client IP preservation on the LB target groups (needed for Allow List inspection)
        for target_group in fargate_service.target_groups:
            target_group.set_attribute('preserve_client_ip.enabled','true')
        
        # Security Group rules - Admin
        for cidr in cfg.ALLOWED_ADMIN_PEERS :
            fargate_service.service.connections.security_groups[0].add_ingress_rule(
                peer = ec2.Peer.ipv4(cidr),
                connection = ec2.Port.tcp(cfg.MIRTH_ADMIN_PORT),
                description="Allow Admin Port from " + cidr
            )
        
        # Security Group rules - Channels
        for port, cidrs in cfg.ALLOWED_CHANNEL_PORTS_AND_PEERS.items() :
            for cidr in cidrs :
                fargate_service.service.connections.security_groups[0].add_ingress_rule(
                    peer = ec2.Peer.ipv4(cidr),
                    connection = ec2.Port.tcp(port),
                    description="Allow Channel Port from " + cidr
                )
        
        self.fargate_service = fargate_service #adding to the main scope as we need to send cluster params to other stacks in the app
        db_instance.connections.allow_from(
            fargate_service.service, 
            ec2.Port.tcp(db_instance.instance_endpoint.port), 
            "Allow Fargate service to access RDS instance"
        )