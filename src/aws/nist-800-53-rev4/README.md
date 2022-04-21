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

| Rule         | Description                                                                                                                        |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| AWS NIS 1.1  | IAM role trust policies should not allow all principals to assume the role                                                         |
| AWS NIS 1.2  | IAM roles attached to instance profiles should not allow broad list actions on S3 buckets                                          |
| AWS NIS 1.3  | S3 bucket ACLs should not have public access on S3 buckets that store CloudTrail log files                                         |
| AWS NIS 2.1  | Auto Scaling groups should span two or more availability zones                                                                     |
| AWS NIS 2.2  | ELBv1 load balancer cross zone load balancing should be enabled                                                                    |
| AWS NIS 2.3  | RDS Aurora cluster multi-AZ should be enabled                                                                                      |
| AWS NIS 2.4  | Require Multi Availability Zones turned on for RDS Instances                                                                       |
| AWS NIS 2.5  | S3 bucket replication (cross-region or same-region) should be enabled                                                              |
| AWS NIS 3.1  | CloudTrail log files should be encrypted with customer managed KMS keys                                                            |
| AWS NIS 3.2  | CloudWatch log groups should be encrypted with customer managed KMS keys                                                           |
| AWS NIS 3.3  | DynamoDB tables should be encrypted with AWS or customer managed KMS keys                                                          |
| AWS NIS 3.4  | EBS volume encryption should be enabled                                                                                            |
| AWS NIS 3.5  | RDS instances should be encrypted                                                                                                  |
| AWS NIS 3.6  | S3 bucket server-side encryption should be enabled                                                                                 |
| AWS NIS 3.7  | SQS queue server-side encryption should be enabled with KMS keys                                                                   |
| AWS NIS 4.1  | CloudFront distribution origin should be set to S3 or origin protocol policy should be set to https-only                           |
| AWS NIS 4.2  | CloudFront viewer protocol policy should be set to https-only or redirect-to-https                                                 |
| AWS NIS 4.3  | ElastiCache transport encryption should be enabled                                                                                 |
| AWS NIS 4.4  | ELBv1 listener protocol should not be set to http                                                                                  |
| AWS NIS 4.5  | S3 bucket policies should only allow requests that use HTTPS                                                                       |
| AWS NIS 4.6  | SNS subscriptions should deny access via HTTP                                                                                      |
| AWS NIS 6.1  | CloudFront access logging should be enabled                                                                                        |
| AWS NIS 6.4  | CloudTrail should have at least one CloudTrail trail set to a multi-region trail                                                   |
| AWS NIS 6.6  | CloudTrail trails should be configured to log management events                                                                    |
| AWS NIS 6.8  | Exactly one CloudTrail trail should monitor global services                                                                        |
| AWS NIS 6.9  | Load balancer access logging should be enabled                                                                                     |
| AWS NIS 6.12 | S3 bucket object-level logging for read events should be enabled                                                                   |
| AWS NIS 6.13 | S3 bucket object-level logging for write events should be enabled                                                                  |
| AWS NIS 8.2  | VPC default security group should restrict all traffic                                                                             |
| AWS NIS 8.9  | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to port 3389 (Remote Desktop Protocol)                         |
| AWS NIS 8.10 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 61621 (Cassandra OpsCenter Agent)              |
| AWS NIS 8.11 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 636 (LDAP SSL)                                 |
| AWS NIS 8.12 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 7001 (Cassandra)                               |
| AWS NIS 8.13 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 11214 (Memcached SSL)                          |
| AWS NIS 8.14 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 11215 (Memcached SSL)                          |
| AWS NIS 8.15 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 135 (MSSQL Debugger)                           |
| AWS NIS 8.16 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 137 (NetBIOS Name Service)                     |
| AWS NIS 8.17 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 138 (NetBios Datagram Service)                 |
| AWS NIS 8.18 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 139 (NetBios Session Service)                  |
| AWS NIS 8.19 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 1433 (MSSQL Server)                                |
| AWS NIS 8.20 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 1434 (MSSQL Admin)                             |
| AWS NIS 8.21 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to port 22 (SSH)                                               |
| AWS NIS 8.22 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 23 (Telnet)                                        |
| AWS NIS 8.23 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 2379 (etcd)                                        |
| AWS NIS 8.24 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 2382 (SQL Server Analysis Services browser)    |
| AWS NIS 8.25 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 2383 (SQL Server Analysis Services)            |
| AWS NIS 8.26 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 2484 (Oracle DB SSL)                           |
| AWS NIS 8.27 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 27017 (MongoDB)                                    |
| AWS NIS 8.28 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 27018 (MongoDB)                                    |
| AWS NIS 8.29 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 27019 (MongoDB)                                    |
| AWS NIS 8.30 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 3000 (Ruby on Rails web server)                |
| AWS NIS 8.31 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 3020 (CIFS / SMB)                              |
| AWS NIS 8.32 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 3306 (MySQL)                                   |
| AWS NIS 8.33 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 4505 (SaltStack Master)                        |
| AWS NIS 8.34 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 4506 (SaltStack Master)                        |
| AWS NIS 8.35 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 5432 (PostgreSQL)                              |
| AWS NIS 8.36 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 5500 (Virtual Network Computing)               |
| AWS NIS 8.37 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 5800 (Virtual Network Computing), unless from ELBs |
| AWS NIS 8.38 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 5900 (Virtual Network Computing)                   |
| AWS NIS 8.39 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 80 (HTTP), unless from ELBs                        |
| AWS NIS 8.40 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP/UDP port 8000 (HTTP Alternate)                          |
| AWS NIS 8.41 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 9200 (Elasticsearch)                               |
| AWS NIS 8.42 | VPC security group rules should not permit ingress from ‘0.0.0.0/0’ to TCP port 9300 (Elasticsearch)                               |
| AWS NIS 8.43 | VPC security groups attached to EC2 instances should not permit ingress from ‘0.0.0.0/0’ to all ports                              |
| AWS NIS 8.44 | VPC security groups attached to EC2 instances should not permit ingress from ‘0.0.0.0/0’ to TCP port 389 (LDAP)                    |
| AWS NIS 8.45 | VPC security groups attached to RDS instances should not permit ingress from ‘0.0.0.0/0’ to all ports                              |
