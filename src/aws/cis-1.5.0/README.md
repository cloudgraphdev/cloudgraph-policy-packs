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
| AWS CIS 5.1   | Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports                                   |
| AWS CIS 5.2   | Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports                                |
| AWS CIS 5.3   | Ensure no security groups allow ingress from ::/0 to remote server administration ports                                     |
| AWS CIS 5.4   | Ensure the default security group of every VPC restricts all traffic                                                        |
| AWS CIS 5.5   | Ensure routing tables for VPC peering are "least access"                                                                    |
