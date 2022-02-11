# PCI Data Security Standard version 3.2.1

Policy Pack based on the [PCI DSS version 3.2.1](https://www.pcisecuritystandards.org/documents/PCI_DSS-QRG-v3_2_1.pdf) benchmark provided by the [Payment Card Industry Data Security Standard (PCI DSS)](https://www.pcisecuritystandards.org/)

## Available Ruleset

| Rule                | Description                                                                  |
| ------------------- | ---------------------------------------------------------------------------- |
| autoscaling-check-1 | Auto Scaling groups associated with a load balancer should use health checks |
| cloudtrail-check-1  | CloudTrail logs should be encrypted at rest using AWS KMS keys               |
| cloudtrail-check-2  | CloudTrail should be enabled                                                 |
| cloudtrail-check-3  | CloudTrail log file validation should be enabled                             |
