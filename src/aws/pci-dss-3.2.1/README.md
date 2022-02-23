# PCI Data Security Standard version 3.2.1

Policy Pack based on the [PCI DSS version 3.2.1](https://www.pcisecuritystandards.org/documents/PCI_DSS-QRG-v3_2_1.pdf) benchmark provided by the [Payment Card Industry Data Security Standard (PCI DSS)](https://www.pcisecuritystandards.org/)

## Available Ruleset

| Rule                | Description                                                                  |
| ------------------- | ---------------------------------------------------------------------------- |
| autoscaling-check-1 | Auto Scaling groups associated with a load balancer should use health checks |
| codebuild-check-1   | CodeBuild GitHub or Bitbucket source repository URLs should use OAuth        |
| cloudtrail-check-1  | CloudTrail logs should be encrypted at rest using AWS KMS keys               |
| cloudtrail-check-2  | CloudTrail should be enabled                                                 |
| cloudtrail-check-3  | CloudTrail log file validation should be enabled                             |
| cloudtrail-check-4  | CloudTrail trails should be integrated with CloudWatch Logs                  |
| iam-check-1         | IAM root user access key should not exist                                    |
| iam-check-2         | IAM users should not have IAM policies attached                              |
| iam-check-3         | IAM policies should not allow full "\*" administrative privileges            |
| ec2-check-1         | Amazon EBS snapshots should not be publicly restorable                                            |
| ec2-check-2         | VPC default security group should prohibit inbound and outbound traffic                                            |
| ec2-check-4         | Unused EC2 EIPs should be removed                                            |
| ec2-check-5         | Security groups should not allow ingress from 0.0.0.0/0 to port 22           |
| ec2-check-6         | VPC flow logging should be enabled in all VPCs                               |
