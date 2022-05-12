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
| AWS CIS 1.11  | Do not setup access keys during initial user setup for all IAM users that have a console password                           |
| AWS CIS 1.18  | Ensure IAM instance roles are used for AWS resource access from instances                                                   |
| AWS CIS 1.22  | Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments          |
| AWS CIS 2.1.1 | Ensure all S3 buckets employ encryption-at-rest                                                                             |
| AWS CIS 2.1.2 | Ensure S3 Bucket Policy allows HTTPS requests                                                                               |
| AWS CIS 2.2.1 | Ensure EBS volume encryption is enabled                                                                                     |
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
| AWS CIS 5.4   | Ensure routing tables for VPC peering are "least access"                                                                    |
