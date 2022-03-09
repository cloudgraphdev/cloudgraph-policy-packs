# PCI Data Security Standard version 3.2.1

Policy Pack based on the [PCI DSS version 3.2.1](https://www.pcisecuritystandards.org/documents/PCI_DSS-QRG-v3_2_1.pdf) benchmark provided by the [Payment Card Industry Data Security Standard (PCI DSS)](https://www.pcisecuritystandards.org/)

## First Steps

1. Install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start).
2. Set up the [AWS Provider](https://www.npmjs.com/package/@cloudgraph/cg-provider-aws) for CG with the `cg init aws` command.
3. Add Policy Pack for AWS PCI DSS benchmark using `cg policy add aws-pci-dss-3.2.1` command.
4. Execute the ruleset using the scan command `cg scan aws`.
5. Query the findings using the different options:

   5a. Querying findings by provider:

   ```graphql
   query {
     queryawsFindings {
       PCIFindings {
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
     queryawsPCIFindings {
       id
       resourceId
       result
     }
   }
   ```

   5c. Querying findings by resource:

   ```graphql
   query {
     queryawsCodebuild {
       id
       arn
       accountId
       PCIFindings {
         id
         resourceId
         result
       }
     }
   }
   ```

## Available Ruleset

| Rule                | Description                                                                           |
| ------------------- | ------------------------------------------------------------------------------------- |
| autoscaling-check-1 | Auto Scaling groups associated with a load balancer should use health checks          |
| alb-check-1         | Application Load Balancer should be configured to redirect all HTTP requests to HTTPS |
| codebuild-check-1   | CodeBuild GitHub or Bitbucket source repository URLs should use OAuth                 |
| codebuild-check-2   | CodeBuild project environment variables should not contain clear text credentials     |
| cloudtrail-check-1  | CloudTrail logs should be encrypted at rest using AWS KMS keys                        |
| cloudtrail-check-2  | CloudTrail should be enabled                                                          |
| cloudtrail-check-3  | CloudTrail log file validation should be enabled                                      |
| cloudtrail-check-4  | CloudTrail trails should be integrated with CloudWatch Logs                           |
| iam-check-1         | IAM root user access key should not exist                                             |
| iam-check-2         | IAM users should not have IAM policies attached                                       |
| iam-check-3         | IAM policies should not allow full "\*" administrative privileges                     |
| ec2-check-1         | Amazon EBS snapshots should not be publicly restorable                                |
| ec2-check-2         | VPC default security group should prohibit inbound and outbound traffic               |
| ec2-check-4         | Unused EC2 EIPs should be removed                                                     |
| ec2-check-5         | Security groups should not allow ingress from 0.0.0.0/0 to port 22                    |
| ec2-check-6         | VPC flow logging should be enabled in all VPCs                                        |
| kms-check-1         | KMS key rotation should be enabled                                                    |
| sageMaker-check-1   | Amazon SageMaker notebook instances should not have direct internet access            |
