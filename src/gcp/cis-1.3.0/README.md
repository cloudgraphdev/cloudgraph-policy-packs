# CIS Google Cloud Platform Foundations 1.3.0

Policy Pack based on the GCP Foundations 1.3.0 benchmark provided by the [Center for Internet Security (CIS)](https://www.cisecurity.org/benchmark/google_cloud_computing_platform/)

## First Steps

1. Install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start).
2. Set up the [GCP Provider](https://www.npmjs.com/package/@cloudgraph/cg-provider-gcp) for CG with the `cg init gcp` command.
3. Add Policy Pack for CIS Google Cloud Platform Foundations benchmark using `cg policy add gcp-cis-1.3.0` command.
4. Execute the ruleset using the scan command `cg scan gcp`.
5. Query the findings using the different options:

   5a. Querying findings by provider:

   ```graphql
   query {
     querygcpFindings {
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
       CISFindings {
         id
         resourceId
         result
       }
     }
   }
   ```

## Available Ruleset

| Rule           | Description                                                                                                                                                         |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GCP CIS 1.1    | Ensure that corporate login credentials are used                                                                                                                    |
| GCP CIS 1.2    | Ensure that multi-factor authentication is enabled for all non-service accounts                                                                                     |
| GCP CIS 1.3    | Ensure that Security Key Enforcement is enabled for all admin accounts                                                                                              |
| GCP CIS 1.4    | Ensure that there are only GCP-managed service account keys for each service account                                                                                |
| GCP CIS 1.5    | Ensure that Service Account has no Admin privileges                                                                                                                 |
| GCP CIS 1.6    | Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level                                             |
| GCP CIS 1.7    | Ensure user-managed/external keys for service accounts are rotated every 90 days or less                                                                            |
| GCP CIS 1.8    | Ensure that Separation of duties is enforced while assigning service account related roles to users                                                                 |
| GCP CIS 1.9    | Ensure that Cloud KMS cryptokeys are not anonymously or publicly accessible                                                                                         |
| GCP CIS 1.10   | Ensure KMS encryption keys are rotated within a period of 90 days                                                                                                   |
| GCP CIS 1.11   | Ensure that Separation of duties is enforced while assigning KMS related roles to users                                                                             |
| GCP CIS 1.12   | Ensure API keys are not created for a project                                                                                                                       |
| GCP CIS 1.13   | Ensure API keys are restricted to use by only specified Hosts and Apps                                                                                              |
| GCP CIS 1.14   | Ensure API keys are restricted to only APIs that application needs access                                                                                           |
| GCP CIS 1.15   | Ensure API keys are rotated every 90 days                                                                                                                           |
| GCP CIS 2.1    | Ensure that Cloud Audit Logging is configured properly across all services and all users from a project                                                             |
| GCP CIS 2.2    | Ensure that sinks are configured for all log entries                                                                                                                |
| GCP CIS 2.3    | Ensure that retention policies on log buckets are configured using Bucket Lock                                                                                      |
| GCP CIS 2.4    | Ensure log metric filter and alerts exist for project ownership assignments/changes                                                                                 |
| GCP CIS 2.5    | Ensure that the log metric filter and alerts exist for Audit Configuration changes                                                                                  |
| GCP CIS 2.6    | Ensure that the log metric filter and alerts exist for Custom Role changes                                                                                          |
| GCP CIS 2.7    | Ensure that the log metric filter and alerts exist for VPC Network Firewall rule changes                                                                            |
| GCP CIS 2.8    | Ensure that the log metric filter and alerts exist for VPC network route changes                                                                                    |
| GCP CIS 2.9    | Ensure that the log metric filter and alerts exist for VPC network changes                                                                                          |
| GCP CIS 2.10   | Ensure that the log metric filter and alerts exist for Cloud Storage IAM permission changes                                                                         |
| GCP CIS 2.11   | Ensure that the log metric filter and alerts exist for SQL instance configuration changes                                                                           |
| GCP CIS 2.12   | Ensure that Cloud DNS logging is enabled for all VPC networks                                                                                                       |
| GCP CIS 2.13   | Ensure Cloud Asset Inventory Is Enabled                                                                                                                             |
| GCP CIS 2.14   | Ensure 'Access Transparency' is 'Enabled'                                                                                                                           |
| GCP CIS 3.1    | Ensure that the default network does not exist in a project                                                                                                         |
| GCP CIS 3.2    | Ensure legacy networks do not exist for a project                                                                                                                   |
| GCP CIS 3.3    | Ensure that DNSSEC is enabled for Cloud DNS                                                                                                                         |
| GCP CIS 3.4    | Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC                                                                                         |
| GCP CIS 3.5    | Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC                                                                                        |
| GCP CIS 3.6    | Ensure that SSH access is restricted from the internet                                                                                                              |
| GCP CIS 3.7    | Ensure that RDP access is restricted from the internet                                                                                                              |
| GCP CIS 3.8    | Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network                                                                                              |
| GCP CIS 3.9    | Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites                                                                             |
| GCP CIS 3.10   | Use Identity Aware Proxy (IAP) to Ensure Only Traffic From Google IP Addresses are 'Allowed'                                                                        |
| GCP CIS 4.1    | Ensure that instances are not configured to use the default service account                                                                                         |
| GCP CIS 4.2    | Ensure that instances are not configured to use the default service account with full access to all Cloud APIs                                                      |
| GCP CIS 4.3    | Ensure "Block Project-wide SSH keys" is enabled for VM instances                                                                                                    |
| GCP CIS 4.4    | Ensure oslogin is enabled for a Project                                                                                                                             |
| GCP CIS 4.5    | Ensure 'Enable connecting to serial ports' is not enabled for VM Instance                                                                                           |
| GCP CIS 4.6    | Ensure that IP forwarding is not enabled on Instances                                                                                                               |
| GCP CIS 4.7    | Ensure VM disks for critical VMs are encrypted with Customer-Supplied Encryption Keys (CSEK)                                                                        |
| GCP CIS 4.8    | Ensure Compute instances are launched with Shielded VM enabled                                                                                                      |
| GCP CIS 4.9    | Ensure that Compute instances do not have public IP addresses                                                                                                       |
| GCP CIS 4.10   | In order to maintain the highest level of security all connections to an application should be secure by default                                                    |
| GCP CIS 4.11   | Ensure that Compute instances have Confidential Computing enabled                                                                                                   |
| GCP CIS 4.12   | Ensure the Latest Operating System Updates Are Installed On Your Virtual Machines in All Projects                                                                   |
| GCP CIS 5.1    | Ensure that Cloud Storage bucket is not anonymously or publicly accessible                                                                                          |
| GCP CIS 5.2    | Ensure that Cloud Storage buckets have uniform bucket-level access enabled                                                                                          |
| GCP CIS 6.1.1  | Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges                                                               |
| GCP CIS 6.1.2  | Ensure 'skip_show_database' database flag for Cloud SQL Mysql instance is set to 'on'                                                                               |
| GCP CIS 6.1.3  | Ensure that the 'local_infile' database flag for a Cloud SQL Mysql instance is set to 'off'                                                                         |
| GCP CIS 6.2.1  | Ensure 'log_error_verbosity' database flag for Cloud SQL PostgreSQL instance is set to 'DEFAULT' or stricter                                                        |
| GCP CIS 6.2.2  | Ensure that the 'log_connections' database flag for Cloud SQL PostgreSQL instance is set to 'on'                                                                    |
| GCP CIS 6.2.3  | Ensure that the 'log_disconnections' database flag for Cloud SQL PostgreSQL instance is set to 'on'                                                                 |
| GCP CIS 6.2.4  | Ensure 'log_statement' database flag for Cloud SQL PostgreSQL instance is set appropriately                                                                         |
| GCP CIS 6.2.5  | Ensure 'log_hostname' database flag for Cloud SQL PostgreSQL instance is set appropriately                                                                          |
| GCP CIS 6.2.6  | Ensure that the 'log_min_messages' database flag for Cloud SQL PostgreSQL instance is set appropriately                                                             |
| GCP CIS 6.2.7  | Ensure 'log_min_error_statement' database flag for Cloud SQL PostgreSQL instance is set to 'Error' or stricter                                                      |
| GCP CIS 6.2.8  | Ensure that the 'log_min_duration_statement' database flag for Cloud SQL PostgreSQL instance is set to '-1' (disabled)                                              |
| GCP CIS 6.2.9  | Ensure That 'cloudsql.enable_pgaudit' Database Flag for each Cloud Sql Postgresql Instance Is Set to 'on' For Centralized Logging                                   |
| GCP CIS 6.3.1  | Ensure 'external scripts enabled' database flag for Cloud SQL SQL Server instance is set to 'off'                                                                   |
| GCP CIS 6.3.2  | Ensure that the 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off'                                                       |
| GCP CIS 6.3.3  | Ensure 'user connections' database flag for Cloud SQL SQL Server instance is set as appropriate                                                                     |
| GCP CIS 6.3.4  | Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured                                                                             |
| GCP CIS 6.3.5  | Ensure 'remote access' database flag for Cloud SQL SQL Server instance is set to 'off'                                                                              |
| GCP CIS 6.3.6  | Ensure '3625 (trace flag)' database flag for Cloud SQL SQL Server instance is set to 'off'                                                                          |
| GCP CIS 6.3.7  | Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is set to 'off'                                          |
| GCP CIS 7.1    | Ensure that BigQuery datasets are not anonymously or publicly accessible                                                                                            |
| GCP CIS 7.2    | Ensure that all BigQuery Tables are encrypted with Customer-managed encryption key                                                                                  |
| GCP CIS 7.3    | Ensure that a Default Customer-managed encryption key (CMEK) is specified for all BigQuery Data Sets                                                                |
