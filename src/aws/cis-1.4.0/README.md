# CIS Amazon Web Services Foundations 1.4.0

Policy Pack based on the [AWS Foundations 1.4.0](https://docs.aws.amazon.com/audit-manager/latest/userguide/CIS-1-4.html) benchmark provided by the [Center for Internet Security (CIS)](https://www.cisecurity.org/benchmark/amazon_web_services/)

## First Steps

1. Install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start).
2. Set up the [AWS Provider](https://www.npmjs.com/package/@cloudgraph/cg-provider-aws) for CG with the `cg init aws` command.
3. Add Policy Pack for CIS Amazon Web Services Foundations benchmark using `cg policy add aws-cis-1.4.0` command.
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

| Rule          | Description                                                                                                                 |
| ------------- | --------------------------------------------------------------------------------------------------------------------------- |
| AWS CIS 1.4   | Ensure no 'root' user account access key exists                                                                             |
| AWS CIS 1.5   | Ensure MFA is enabled for the 'root' user account                                                                           |
| AWS CIS 1.6   | Ensure hardware MFA is enabled for the 'root' user account                                                                  |
| AWS CIS 1.7   | Eliminate use of the 'root' user for administrative and daily tasks                                                         |
| AWS CIS 1.8   | Ensure IAM password policy requires minimum length of 14 or greater                                                         |
| AWS CIS 1.9   | Ensure IAM password policy prevents password reuse                                                                          |
| AWS CIS 1.10  | Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password                          |
| AWS CIS 1.12  | Ensure credentials unused for 45 days or greater are disabled                                                               |
| AWS CIS 1.13  | Ensure there is only one active access key available for any single IAM user                                                |
| AWS CIS 1.14  | Ensure access keys are rotated every 90 days or less                                                                        |
| AWS CIS 1.15  | Ensure IAM Users Receive Permissions Only Through Groups                                                                    |
| AWS CIS 1.16  | Ensure IAM policies that allow full "*:*" administrative privileges are not attached                                        |
| AWS CIS 1.17  | Ensure a support role has been created to manage incidents with AWS Support                                                 |
| AWS CIS 1.19  | Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed                                              |
| AWS CIS 1.20  | Ensure that IAM Access analyzer is enabled for all regions                                                                  |
| AWS CIS 1.21  | Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments (Manual) |
