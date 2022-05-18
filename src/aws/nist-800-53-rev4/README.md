# NIST 800-53 Rev. 4 for Amazon Web Services

Policy Pack based on the [800-53 Rev. 4](https://csrc.nist.gov/publications/detail/sp/800-53/rev-4/archive/2015-01-22) benchmark provided by the [The National Institute of Standards and Technology (NIST)](https://www.nist.gov)

## First Steps

1. Install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start).
2. Set up the [AWS Provider](https://www.npmjs.com/package/@cloudgraph/cg-provider-aws) for CG with the `cg init aws` command.
3. Add Policy Pack NIST 800-53 Rev. 4 for Amazon Web Services benchmark using `cg policy add aws-nist-800-53-rev4` command.
4. Execute the ruleset using the scan command `cg scan aws`.
5. Query the findings using the different options:

   5a. Querying findings by provider:

   ```graphql
   query {
     queryawsFindings {
       NISTFindings {
         id
         resourceId
         result
       }
     }
   }
   ```

   5b. Querying findings by specific benchmark:

   ```graphql
   query {
     queryawsNISTFindings {
       id
       resourceId
       result
     }
   }
   ```

   5c. Querying findings by resource:

   ```graphql
   query {
     queryawsIamUser {
       id
       arn
       accountId
       NISTFindings {
         id
         resourceId
         result
       }
     }
   }
   ```


## Available Ruleset

| Rule          | Description                                                                                                                        |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| AWS NIST 1.1  | IAM role trust policies should not allow all principals to assume the role                                                         |
| AWS NIST 1.2  | IAM roles attached to instance profiles should not allow broad list actions on S3 buckets                                          |
| AWS NIST 1.3  | S3 bucket ACLs should not have public access on S3 buckets that store CloudTrail log files                                         |
| AWS NIST 2.1  | Auto Scaling groups should span two or more availability zones                                                                     |
| AWS NIST 2.2  | ELBv1 load balancer cross zone load balancing should be enabled                                                                    |
| AWS NIST 2.3  | RDS Aurora cluster multi-AZ should be enabled                                                                                      |
| AWS NIST 2.4  | Require Multi Availability Zones turned on for RDS Instances                                                                       |
| AWS NIST 2.5  | S3 bucket replication (cross-region or same-region) should be enabled                                                              |
| AWS NIST 3.1  | CloudTrail log files should be encrypted with customer managed KMS keys                                                            |
| AWS NIST 3.2  | CloudWatch log groups should be encrypted with customer managed KMS keys                                                           |
| AWS NIST 3.3  | DynamoDB tables should be encrypted with AWS or customer managed KMS keys                                                          |
| AWS NIST 3.4  | EBS volume encryption should be enabled                                                                                            |
| AWS NIST 3.5  | RDS instances should be encrypted                                                                                                  |
| AWS NIST 3.6  | S3 bucket server-side encryption should be enabled                                                                                 |
| AWS NIST 3.7  | SQS queue server-side encryption should be enabled with KMS keys                                                                   |
| AWS NIST 4.1  | CloudFront distribution origin should be set to S3 or origin protocol policy should be set to https-only                           |
| AWS NIST 4.2  | CloudFront viewer protocol policy should be set to https-only or redirect-to-https                                                 |
| AWS NIST 4.3  | ElastiCache transport encryption should be enabled                                                                                 |
| AWS NIST 4.4  | ELBv1 listener protocol should not be set to http                                                                                  |
| AWS NIST 4.5  | S3 bucket policies should only allow requests that use HTTPS                                                                       |
| AWS NIST 4.6  | SNS subscriptions should deny access via HTTP                                                                                      |
| AWS NIST 5.1  | RDS instances should have FedRAMP approved database engines                                                                        |
| AWS NIST 6.1  | CloudFront access logging should be enabled                                                                                        |
| AWS NIST 6.2  | CloudTrail log file validation should be enabled                                                                                   |
| AWS NIST 6.3  | CloudTrail should be enabled in all regions                                                                                        |
| AWS NIST 6.4  | CloudTrail should have at least one CloudTrail trail set to a multi-region trail                                                   |
| AWS NIST 6.5  | CloudTrail trails should be configured to log data events for S3 buckets                                                           |
| AWS NIST 6.6  | CloudTrail trails should be configured to log management events                                                                    |
| AWS NIST 6.7  | CloudTrail trails should have CloudWatch log integration enabled                                                                   |
| AWS NIST 6.8  | Exactly one CloudTrail trail should monitor global services                                                                        |
| AWS NIST 6.9  | Load balancer access logging should be enabled                                                                                     |
| AWS NIST 6.10 | S3 bucket access logging should be enabled                                                                                         |
| AWS NIST 6.11 | S3 bucket access logging should be enabled on S3 buckets that store CloudTrail log files                                           |
| AWS NIST 6.12 | S3 bucket object-level logging for read events should be enabled                                                                   |
| AWS NIST 6.13 | S3 bucket object-level logging for write events should be enabled                                                                  |
| AWS NIST 6.14 | VPC flow logging should be enabled                                                                                                 |
| AWS NIST 7.1  | Alarm for denied connections in CloudFront logs should be configured                                                               |
| AWS NIST 7.3  | CloudWatch log metric filter and alarm for AWS Organizations changes should be configured for the master account                   |
| AWS NIST 7.3  | CloudWatch log metric filter and alarm for changes to VPC NACLs should be configured                                               |
| AWS NIST 7.4  | CloudWatch log metric filter and alarm for changes to VPC network gateways should be configured                                    |
| AWS NIST 7.5  | CloudWatch log metric filter and alarm for CloudTrail configuration changes should be configured                                   |
| AWS NIST 7.7  | CloudWatch log metric filter and alarm for IAM policy changes should be configured                                                 |
| AWS NIST 7.8  | CloudWatch log metric filter and alarm for Management Console authentication failures should be configured                         |
| AWS NIST 7.9  | CloudWatch log metric filter and alarm for Management Console sign-in without MFA should be configured                             |
| AWS NIST 7.10 | CloudWatch log metric filter and alarm for unauthorized API calls should be configured                                             |
| AWS NIST 7.11 | CloudWatch log metric filter and alarm for usage of root account should be configured                                              |
| AWS NIST 7.12 | CloudWatch log metric filter and alarm for VPC changes should be configured                                                        |
| AWS NIST 7.13 | CloudWatch log metric filter and alarm for VPC route table changes should be configured                                            |
| AWS NIST 7.14 | CloudWatch log metric filter and alarm for VPC security group changes should be configured                                         |
| AWS NIST 8.1  | ELB listener security groups should not be set to TCP all                                                                          |
| AWS NIST 8.2  | VPC default security group should restrict all traffic                                                                             |
| AWS NIST 8.3  | VPC network ACLs should not allow ingress from 0.0.0.0/0 to TCP/UDP port 22                                                        |
| AWS NIST 8.4  | AWS NIST 8.4 VPC network ACLs should not allow ingress from 0.0.0.0/0 to TCP/UDP port 3389                                         |
| AWS NIST 8.5  | VPC security group inbound rules should not permit ingress from ‘0.0.0.0/0’ to all ports and protocols                             |
| AWS NIST 8.6  | VPC security group inbound rules should not permit ingress from a public address to all ports and protocols                        |
| AWS NIST 8.7  | VPC security group inbound rules should not permit ingress from any address to all ports and protocols                             |
| AWS NIST 8.8  | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ except to ports 80 and 443                                     |
| AWS NIST 8.9  | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to port 3389 (Remote Desktop Protocol)                         |
| AWS NIST 8.10 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 61621 (Cassandra OpsCenter Agent)              |
| AWS NIST 8.11 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 636 (LDAP SSL)                                 |
| AWS NIST 8.12 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 7001 (Cassandra)                               |
| AWS NIST 8.13 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 11214 (Memcached SSL)                          |
| AWS NIST 8.14 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 11215 (Memcached SSL)                          |
| AWS NIST 8.15 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 135 (MSSQL Debugger)                           |
| AWS NIST 8.16 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 137 (NetBIOS Name Service)                     |
| AWS NIST 8.17 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 138 (NetBios Datagram Service)                 |
| AWS NIST 8.18 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 139 (NetBios Session Service)                  |
| AWS NIST 8.19 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 1433 (MSSQL Server)                                |
| AWS NIST 8.20 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 1434 (MSSQL Admin)                             |
| AWS NIST 8.21 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to port 22 (SSH)                                               |
| AWS NIST 8.22 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 23 (Telnet)                                        |
| AWS NIST 8.23 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 2379 (etcd)                                        |
| AWS NIST 8.24 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 2382 (SQL Server Analysis Services browser)    |
| AWS NIST 8.25 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 2383 (SQL Server Analysis Services)            |
| AWS NIST 8.26 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 2484 (Oracle DB SSL)                           |
| AWS NIST 8.27 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 27017 (MongoDB)                                    |
| AWS NIST 8.28 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 27018 (MongoDB)                                    |
| AWS NIST 8.29 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 27019 (MongoDB)                                    |
| AWS NIST 8.30 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 3000 (Ruby on Rails web server)                |
| AWS NIST 8.31 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 3020 (CIFS / SMB)                              |
| AWS NIST 8.32 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 3306 (MySQL)                                   |
| AWS NIST 8.33 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 4505 (SaltStack Master)                        |
| AWS NIST 8.34 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 4506 (SaltStack Master)                        |
| AWS NIST 8.35 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 5432 (PostgreSQL)                              |
| AWS NIST 8.36 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 5500 (Virtual Network Computing)               |
| AWS NIST 8.37 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 5800 (Virtual Network Computing), unless from ELBs |
| AWS NIST 8.38 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 5900 (Virtual Network Computing)                   |
| AWS NIST 8.39 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 80 (HTTP), unless from ELBs                        |
| AWS NIST 8.40 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 8000 (HTTP Alternate)                          |
| AWS NIST 8.41 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 9200 (Elasticsearch)                               |
| AWS NIST 8.42 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 9300 (Elasticsearch)                               |
| AWS NIST 8.43 | VPC security groups attached to EC2 instances should not permit ingress from ‘0.0.0.0/0’ to all ports                              |
| AWS NIST 8.44 | VPC security groups attached to EC2 instances should not permit ingress from ‘0.0.0.0/0’ to TCP port 389 (LDAP)                    |
| AWS NIST 8.45 | VPC security groups attached to RDS instances should not permit ingress from ‘0.0.0.0/0’ to all ports                              |
| AWS NIST 9.1  | ECS container definitions should not mount volumes with mount propagation set to shared                                            |
| AWS NIST 9.2  | ECS task definitions should mount the container’s root filesystem as read-only                                                     |
| AWS NIST 9.3  | ECS task definitions should not add Linux capabilities beyond defaults and should drop ‘NET_RAW’                                   |
| AWS NIST 9.4  | ECS task definitions should not mount sensitive host system directories                                                            |
| AWS NIST 10.1 | IAM password policies should expire passwords within 90 days                                                                       |
| AWS NIST 10.2 | IAM password policies should have a minimum length of 7 and include both alphabetic and numeric characters                         |
| AWS NIST 10.3 | IAM password policies should prevent reuse of previously used passwords                                                            |
| AWS NIST 10.4 | IAM password policies should prevent reuse of the four previously used passwords                                                   |
| AWS NIST 10.5 | IAM password policies should require at least one lowercase character                                                              |
| AWS NIST 10.6 | IAM password policies should require at least one number                                                                           |
| AWS NIST 10.7 | IAM password policies should require at least one symbol                                                                           |
| AWS NIST 10.8 | IAM password policies should require at least one uppercase character                                                              |
| AWS NIST 11.1 | ECS task definitions should limit memory usage for containers                                                                      |
| AWS NIST 11.2 | ECS task definitions should set CPU limit for containers                                                                           |
| AWS NIST 12.1 | CloudFront distributions should have geo-restrictions specified                                                                    |
| AWS NIST 12.2 | EC2 instances should not have a public IP association (IPv4)                                                                       |
| AWS NIST 13.1 | IAM multi-factor authentication should be enabled for all IAM users that have a console password                                   |
| AWS NIST 13.2 | IAM should have hardware MFA enabled for the root account                                                                          |
| AWS NIST 13.3 | IAM should have MFA enabled for the root account                                                                                   |
| AWS NIST 13.4 | IAM users should have MFA (virtual or hardware) enabled                                                                            |
| AWS NIST 14.1 | CloudFront distributions should be protected by WAFs                                                                               |
| AWS NIST 15.1 | ECS task definitions should not use the root user                                                                                  |
| AWS NIST 15.2 | IAM roles used for trust relationships should have MFA or external IDs                                                             |
| AWS NIST 15.3 | IAM root user access key should not exist                                                                                          |
| AWS NIST 15.4 | IAM root user should not be used                                                                                                   |
| AWS NIST 16.1 | API Gateway classic custom domains should use secure TLS protocol versions (1.2 and above)                                         |
| AWS NIST 16.2 | API Gateway v2 custom domains should use secure TLS protocol versions (1.2 and above)                                              |
| AWS NIST 16.3 | CloudFront distribution custom origins should use secure TLS protocol versions (1.2 and above)                                     |
| AWS NIST 16.4 | CloudFront distribution viewer certificate should use secure TLS protocol versions (1.2 and above)                                 |
| AWS NIST 16.5 | ELB HTTPS listeners should use secure TLS protocol versions (1.2 and above)                                                        |
| AWS NIST 16.6 | ELBv2 HTTPS listeners should use secure TLS protocol versions (1.2 and above)                                                      |