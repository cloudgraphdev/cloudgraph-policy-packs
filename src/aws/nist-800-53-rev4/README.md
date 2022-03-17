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

| Rule         | Description                                                                                              |
| ------------ | -------------------------------------------------------------------------------------------------------- |
| AWS NIS 3.1  | CloudTrail log files should be encrypted with customer managed KMS keys                                  |
| AWS NIS 3.2  | CloudWatch log groups should be encrypted with customer managed KMS keys                                 |
| AWS NIS 3.3  | DynamoDB tables should be encrypted with AWS or customer managed KMS keys                                |
| AWS NIS 3.4  | EBS volume encryption should be enabled                                                                  |
| AWS NIS 3.5  | RDS instances should be encrypted                                                                        |
| AWS NIS 3.6  | S3 bucket server-side encryption should be enabled                                                       |
| AWS NIS 3.7  | SQS queue server-side encryption should be enabled with KMS keys                                         |
| AWS NIS 4.1  | CloudFront distribution origin should be set to S3 or origin protocol policy should be set to https-only |
| AWS NIS 4.2  | CloudFront viewer protocol policy should be set to https-only or redirect-to-https                       |
| AWS NIS 4.3  | ElastiCache transport encryption should be enabled                                                       |
| AWS NIS 4.4  | ELBv1 listener protocol should not be set to http                                                        |
| AWS NIS 4.5  | S3 bucket policies should only allow requests that use HTTPS                                             |
| AWS NIS 4.6  | SNS subscriptions should deny access via HTTP                                                            |
