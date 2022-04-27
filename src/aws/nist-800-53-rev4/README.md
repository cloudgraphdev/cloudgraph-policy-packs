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
| AWS NIST 6.1  | CloudFront access logging should be enabled                                                                                        |
| AWS NIST 6.4  | CloudTrail should have at least one CloudTrail trail set to a multi-region trail                                                   |
| AWS NIST 6.6  | CloudTrail trails should be configured to log management events                                                                    |
| AWS NIST 6.8  | Exactly one CloudTrail trail should monitor global services                                                                        |
| AWS NIST 6.9  | Load balancer access logging should be enabled                                                                                     |
| AWS NIST 6.12 | S3 bucket object-level logging for read events should be enabled                                                                   |
| AWS NIST 6.13 | S3 bucket object-level logging for write events should be enabled                                                                  |
| AWS NIST 13.1 | IAM multi-factor authentication should be enabled for all IAM users that have a console password                                   |
| AWS NIST 13.2 | IAM should have hardware MFA enabled for the root account                                                                          |
| AWS NIST 13.3 | IAM should have MFA enabled for the root account                                                                                   |
| AWS NIST 13.4 | IAM users should have MFA (virtual or hardware) enabled                                                                            |
