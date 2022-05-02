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
| AWS CIS 1.1   | Maintain current contact details (Manual)                                                                                   |
| AWS CIS 1.2   | Ensure security contact information is registered (Manual)                                                                  |
| AWS CIS 1.3   | Ensure security questions are registered in the AWS account                                                                 |
| AWS CIS 1.11  | Do not setup access keys during initial user setup for all IAM users that have a console password (Manual)                  |
| AWS CIS 1.18  | Ensure IAM instance roles are used for AWS resource access from instances (Manual)                                          |
| AWS CIS 1.22  | Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments (Manual) |
| AWS CIS 2.1.1 | Ensure all S3 buckets employ encryption-at-rest (Manual)                                                                    |
| AWS CIS 2.1.2 | Ensure S3 Bucket Policy allows HTTPS requests (Manual)                                                                      |
| AWS CIS 2.2.1 | Ensure EBS volume encryption is enabled (Manual)                                                                            |
| AWS CIS 5.4   | Ensure routing tables for VPC peering are "least access" (Manual)                                                           |
