# PCI Data Security Standard version 3.2.1

Policy Pack based on the [PCI DSS version 3.2.1](https://www.pcisecuritystandards.org/documents/PCI_DSS-QRG-v3_2_1.pdf) benchmark provided by the [Payment Card Industry Data Security Standard (PCI DSS)](https://www.pcisecuritystandards.org/)

## Available Ruleset

| Rule                | Description                                                                  |
| ------------------- | ---------------------------------------------------------------------------- |
| autoscaling-check-1 | Auto Scaling groups associated with a load balancer should use health checks |
| cloudtrail-check-1  | CloudTrail logs should be encrypted at rest using AWS KMS keys               |
| cloudtrail-check-2  | CloudTrail should be enabled                                                 |
| cloudtrail-check-3  | CloudTrail log file validation should be enabled                             |
| cloudtrail-check-4  | CloudTrail trails should be integrated with CloudWatch Logs                  |
| iam-check-1         | IAM root user access key should not exist                                    |
| iam-check-2         | IAM users should not have IAM policies attached                              |
| iam-check-3         | IAM policies should not allow full "\*" administrative privileges            |
| ec2-check-5         | Security groups should not allow ingress from 0.0.0.0/0 to port 22           |
| ec2-check-6         | VPC flow logging should be enabled in all VPCs                               |

**To remove access to port 22 from a security group**

1. Open the Amazon VPC console at https://console.aws.amazon.com/vpc/.

1. In the navigation pane, under **Security**, choose **Security groups**.

1. Select a security group.

1. In the bottom section of the page, choose **Inbound rules**.

1. Choose **Edit inbound rules**.

1. Identify the rule that allows access through port 22 and then choose the X to remove it.

1. Choose **Save rules**.
