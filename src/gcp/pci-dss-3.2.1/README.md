# PCI Data Security Standard version 3.2.1

Policy Pack based on the [PCI DSS version 3.2.1](https://www.pcisecuritystandards.org/documents/PCI_DSS-QRG-v3_2_1.pdf) benchmark provided by the [Payment Card Industry Data Security Standard (PCI DSS)](https://www.pcisecuritystandards.org/)

## First Steps

1. Install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start).
2. Set up the [GCP Provider](https://www.npmjs.com/package/@cloudgraph/cg-provider-gcp) for CG with the `cg init gcp` command.
3. Add Policy Pack for GCP PCI DSS benchmark using `cg policy add gcp-pci-dss-3.2.1` command.
4. Execute the ruleset using the scan command `cg scan gcp`.
5. Query the findings using the different options:

   5a. Querying findings by provider:

   ```graphql
   query {
     querygcpFindings {
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
     querygcpCISFindings {
       id
       resourceId
       result
     }
   }
   ```

   5c. Querying findings by resource:

   ```graphql
   query {
     querygcpIamPolicy {
       id
       PCIFindings {
         id
         resourceId
         result
       }
     }
   }
   ```

## Available Ruleset

| Rule               | Description                                                                                                                   |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| iam-check-1        | IAM users should not have both KMS admin and any of the KMS encrypter/decrypter roles                                         |
| iam-check-2        | IAM users should not have project-level "Service Account User" or "Service Account Token Creator" roles                       |
| monitoring-check-1 | Logging metric filter and alert for audit configuration changes should be configured                                          |
| monitoring-check-2 | Logging metric filter and alert for Custom Role changes should be configured                                                  |
| monitoring-check-3 | Logging metric filter and alert for network changes should be configured                                                      |
| monitoring-check-4 | Logging metric filter and alert for network firewall rule changes should be configured                                        |
| monitoring-check-5 | Logging metric filter and alert for network route changes should be configured                                                |
| monitoring-check-6 | Logging metric filter and alert for project ownership assignments/changes should be configured                                |
| monitoring-check-7 | Logging metric filter and alert for SQL instance configuration changes should be configured                                   |
| monitoring-check-8 | Logging metric filter and alert for Storage IAM permission changes should be configured                                       |
| networking-check-1 | Network firewall rules should not permit ingress from 0.0.0.0/0 to port 22 (SSH)                                              |
| networking-check-2 | Network firewall rules should not permit ingress from 0.0.0.0/0 to port 3389 (RDP)                                            |
| networking-check-3 | The default network for a project should be deleted                                                                           |
| networking-check-4 | Load balancer HTTPS or SSL proxy SSL policies should not have weak cipher suites                                              |
| logging-check-1    | At least one project-level logging sink should be configured with an empty filter                                             |
