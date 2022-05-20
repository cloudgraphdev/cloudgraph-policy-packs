# CIS Amazon Web Services Foundations 1.3.0

Policy Pack based on the [AWS Foundations 1.3.0](https://docs.aws.amazon.com/audit-manager/latest/userguide/CIS-1-3.html) benchmark provided by the [Center for Internet Security (CIS)](https://www.cisecurity.org/benchmark/amazon_web_services/)

## First Steps

1. Install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start).
2. Set up the [AWS Provider](https://www.npmjs.com/package/@cloudgraph/cg-provider-aws) for CG with the `cg init aws` command.
3. Add Policy Pack for CIS Amazon Web Services Foundations benchmark using `cg policy add aws-cis-1.3.0` command.
4. Execute the ruleset using the scan command `cg scan aws`.
5. Query the findings using the different options:

   5a. Querying findings by provider:

   ```graphql
   query {
     queryawsFindings {
       CISFindings {
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
     queryawsCISFindings {
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
       CISFindings {
         id
         resourceId
         result
       }
     }
   }
   ```

## Available Ruleset

| Rule          | Description                                                                                                                 |
| ------------- | --------------------------------------------------------------------------------------------------------------------------- |
| AWS CIS 1.1   | Maintain current contact details                                                                                            |
| AWS CIS 1.2   | Ensure security contact information is registered                                                                           |
| AWS CIS 1.3   | Ensure security questions are registered in the AWS account                                                                 |
| AWS CIS 1.4   | Ensure no 'root' user account access key exists                                                                             |
| AWS CIS 1.5   | Ensure MFA is enabled for the 'root user' account                                                                           |
| AWS CIS 1.6   | Ensure hardware MFA is enabled for the 'root' user account                                                                  |
| AWS CIS 1.7   | Eliminate use of the root user for administrative and daily tasks                                                           |
| AWS CIS 1.8   | Ensure IAM password policy requires minimum length of 14 or greater                                                         |
| AWS CIS 1.9   | Ensure IAM password policy prevents password reuse                                                                          |
| AWS CIS 1.10  | Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password                          |
| AWS CIS 1.11  | Do not setup access keys during initial user setup for all IAM users that have a console password                           |
| AWS CIS 1.12  | Ensure credentials unused for 90 days or greater are disabled                                                               |
| AWS CIS 1.13  | Ensure there is only one active access key available for any single IAM user                                                |
| AWS CIS 1.14  | Ensure access keys are rotated every 90 days or less                                                                        |
| AWS CIS 1.15  | Ensure IAM Users Receive Permissions Only Through Groups                                                                    |
| AWS CIS 1.16  | Ensure IAM policies that allow full "*:*" administrative privileges are not attached                                        |
| AWS CIS 1.17  | Ensure a support role has been created to manage incidents with AWS Support                                                 |
| AWS CIS 1.18  | Ensure IAM instance roles are used for AWS resource access from instances                                                   |
| AWS CIS 1.19  | Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed                                              |
| AWS CIS 1.20  | Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'                                          |
| AWS CIS 1.21  | Ensure that IAM Access analyzer is enabled                                                                                  |
| AWS CIS 1.22  | Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments          |
| AWS CIS 2.1.1 | Ensure all S3 buckets employ encryption-at-rest                                                                             |
| AWS CIS 2.1.2 | Ensure S3 Bucket Policy allows HTTPS requests                                                                               |
| AWS CIS 2.2.1 | Ensure EBS volume encryption is enabled                                                                                     |
| AWS CIS 3.1   | Ensure CloudTrail is enabled in all regions                                                                                 |
| AWS CIS 3.2   | Ensure CloudTrail log file validation is enabled                                                                            |
| AWS CIS 3.3   | Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible                                               |
| AWS CIS 3.4   | Ensure CloudTrail trails are integrated with CloudWatch Logs                                                                |
| AWS CIS 3.5   | Ensure AWS Config is enabled in all regions                                                                                 |
| AWS CIS 3.6   | Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket                                                      |
| AWS CIS 3.7   | Ensure CloudTrail logs are encrypted at rest using KMS CMKs                                                                 |
| AWS CIS 3.8   | Ensure rotation for customer created CMKs is enabled                                                                        |
| AWS CIS 3.9   | Ensure VPC flow logging is enabled in all VPCs                                                                              |
| AWS CIS 3.10  | Ensure that Object-level logging for write events is enabled for S3 bucket                                                  |
| AWS CIS 3.11  | Ensure that Object-level logging for read events is enabled for S3 bucket                                                   |
| AWS CIS 4.1   | Ensure a log metric filter and alarm exist for unauthorized API calls                                                       |
| AWS CIS 4.2   | Ensure a log metric filter and alarm exist for Management Console sign-in without MFA                                       |
| AWS CIS 4.3   | Ensure a log metric filter and alarm exist for usage of 'root' account                                                      |
| AWS CIS 4.4   | Ensure a log metric filter and alarm exist for IAM policy changes                                                           |
| AWS CIS 4.5   | Ensure a log metric filter and alarm exist for CloudTrail configuration changes                                             |
| AWS CIS 4.6   | Ensure a log metric filter and alarm exist for AWS Management Console authentication failures                               |
| AWS CIS 4.7   | Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs                     |
| AWS CIS 4.8   | Ensure a log metric filter and alarm exist for S3 bucket policy changes                                                     |
| AWS CIS 4.9   | Ensure a log metric filter and alarm exist for AWS Config configuration changes                                             |
| AWS CIS 4.10  | Ensure a log metric filter and alarm exist for security group changes                                                       |
| AWS CIS 4.11  | Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)                               |
| AWS CIS 4.12  | Ensure a log metric filter and alarm exist for changes to network gateways                                                  |
| AWS CIS 4.13  | Ensure a log metric filter and alarm exist for route table changes                                                          |
| AWS CIS 4.14  | Ensure a log metric filter and alarm exist for VPC changes                                                                  |
| AWS CIS 4.15  | Ensure a log metric filter and alarm exists for AWS Organizations changes                                                   |
| AWS CIS 5.1   | Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports                                   |
| AWS CIS 5.2   | Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports                                |
| AWS CIS 5.3   | Ensure the default security group of every VPC restricts all traffic                                                        |
| AWS CIS 5.4   | Ensure routing tables for VPC peering are "least access"                                                                    |
