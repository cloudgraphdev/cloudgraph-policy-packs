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
| AWS CIS 2.1.1 | Ensure all S3 buckets employ encryption-at-rest                                                                             |
| AWS CIS 2.1.2 | Ensure S3 Bucket Policy allows HTTPS requests                                                                               |
| AWS CIS 2.1.3 | Ensure MFA Delete is enable on S3 buckets                                                                                   |
| AWS CIS 2.1.4 | Ensure all data in Amazon S3 has been discovered, classified and secured when required.                                     |
| AWS CIS 2.1.5 | Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'                                          |
| AWS CIS 2.2.1 | Ensure EBS volume encryption is enabled                                                                                     |
| AWS CIS 2.3.1 | Ensure that encryption is enabled for RDS Instances                                                                         |
