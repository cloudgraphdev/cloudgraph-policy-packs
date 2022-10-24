# CIS Amazon Web Services Foundations 1.5.0

Policy Pack based on the [AWS Foundations 1.5.0](https://drive.google.com/file/d/10EoDf68wxwA2fmgAntElaX_-r6L5qf4B/view?usp=sharing) benchmark provided by the [Center for Internet Security (CIS)](https://www.cisecurity.org/benchmark/amazon_web_services/)

## First Steps

1. Install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start).
2. Set up the [AWS Provider](https://www.npmjs.com/package/@cloudgraph/cg-provider-aws) for CG with the `cg init aws` command.
3. Add Policy Pack for CIS Amazon Web Services Foundations benchmark using `cg policy add aws-cis-1.5.0` command.
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
| AWS CIS 3.11  | Ensure that Object-level logging for read events is enabled for S3 bucket  
