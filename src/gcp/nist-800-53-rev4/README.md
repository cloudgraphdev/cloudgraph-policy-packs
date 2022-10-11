# NIST 800-53 Rev. 4 for Google Cloud Services

Policy Pack based on the [800-53 Rev. 4](https://csrc.nist.gov/publications/detail/sp/800-53/rev-4/archive/2015-01-22) benchmark provided by the [The National Institute of Standards and Technology (NIST)](https://www.nist.gov)

## First Steps

1. Install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start).
2. Set up the [GCP Provider](https://www.npmjs.com/package/@cloudgraph/cg-provider-gcp) for CG with the `cg init gcp` command.
3. Add Policy Pack NIST 800-53 Rev. 4 for Google Cloud Services benchmark using `cg policy add gcp-nist-800-53-rev4` command.
4. Execute the ruleset using the scan command `cg scan gcp`.
5. Query the findings using the different options:

   5a. Querying findings by provider:

   ```graphql
   query {
     querygcpFindings {
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
     querygcpNISTFindings {
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
       NISTFindings {
         id
         resourceId
         result
       }
     }
   }
   ```

## Available Ruleset

| Rule          | Description                                                                                                                        |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| GCP NIST 1.1  | Compute instances should not use the default service account                                                                       |
| GCP NIST 1.2  | Compute instances should not use the default service account with full access to all Cloud APIs                                    |
| GCP NIST 1.3  | Compute instance "block-project-ssh-keys should be enabled                                                                         |
| GCP NIST 1.4  | Compute instances should not have public IP addresses                                                                              |
| GCP NIST 1.5  | Compute instances "Enable connecting to serial ports" should not be enabled                                                        |
| GCP NIST 1.6  | SQL database instances should not permit access from 0.0.0.0/0                                                                     |
| GCP NIST 1.7  | SQL database instances should not have public IPs                                                                                  |
| GCP NIST 2.1  | DNS managed zone DNSSEC should be enabled                                                                                          |
| GCP NIST 2.2  | DNS managed zone DNSSEC key-signing keys should not use RSASHA1                                                                    |
| GCP NIST 2.3  | DNS managed zone DNSSEC zone-signing keys should not use RSASHA1                                                                   |
| GCP NIST 3.1  | IAM default audit log config should not exempt any users                                                                           |
| GCP NIST 3.2  | PostgreSQL database instance 'log_checkpoints' database flag should be set to 'on'                                                 |
| GCP NIST 3.3  | PostgreSQL database instance 'log_connections' database flag should be set to 'on'                                                 |
| GCP NIST 3.4  | PostgreSQL database instance 'log_disconnections' database flag should be set to 'on'                                              |
| GCP NIST 3.5  | PostgreSQL database instance 'log_lock_waits' database flag should be set to 'on'                                                  |
| GCP NIST 3.6  | PostgreSQL database instance 'log_min_error_statement' database flag should be set appropriately                                   |
| GCP NIST 3.7  | PostgreSQL database instance 'log_temp_files' database flag should be set to '0' (on)                                              |
| GCP NIST 3.8  | PostgreSQL database instance 'log_min_duration_statement' database flag should be set to '-1' (disabled)                           |
| GCP NIST 3.9  | At least one project-level logging sink should be configured with an empty filter                                                  |
| GCP NIST 3.10 | Network subnet flow logs should be enabled                                                                                         |
| GCP NIST 3.11 | IAM default audit log config should include 'DATA_READ' and 'DATA_WRITE' log types                                                 |
| GCP NIST 4.1  | Compute instance disks should be encrypted with customer-supplied encryption keys (CSEKs)                                          |
| GCP NIST 4.2  | SQL database instances should require incoming connections to use SSL                                                              |
| GCP NIST 5.1  | Logging metric filter and alert for project ownership assignments/changes should be configured                                     |
| GCP NIST 5.2  | Logging metric filter and alert for audit configuration changes should be configured                                               |
| GCP NIST 5.3  | Logging metric filter and alert for Custom Role changes should be configured                                                       |
| GCP NIST 5.4  | Logging metric filter and alert for network firewall rule changes should be configured                                             |
| GCP NIST 5.5  | Logging metric filter and alert for network route changes should be configured                                                     |
| GCP NIST 5.6  | Logging metric filter and alert for network changes should be configured                                                           |
| GCP NIST 5.7  | Logging metric filter and alert for SQL instance configuration changes should be configured                                        |
| GCP NIST 5.8  | Logging storage bucket retention policies and Bucket Lock should be configured                                                     |
| GCP NIST 6.1  | The default network for a project should be deleted                                                                                |
| GCP NIST 6.2  | Network firewall rules should not permit ingress from 0.0.0.0/0 to port 22 (SSH)                                                   |
| GCP NIST 6.3  | Network firewall rules should not permit ingress from 0.0.0.0/0 to port 3389 (RDP)                                                 |
| GCP NIST 6.4  | Load balancer HTTPS or SSL proxy SSL policies should not have weak cipher suites                                                   |
| GCP NIST 6.5  | Compute instances "IP forwarding" should not be enabled                                                                            |
