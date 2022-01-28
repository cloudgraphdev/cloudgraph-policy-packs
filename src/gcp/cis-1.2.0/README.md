# CIS Google Cloud Platform Foundations 1.2.0

Policy Pack based on the GCP Foundations 1.2.0 benchmark provided by the [Center for Internet Security (CIS)](https://www.cisecurity.org/benchmark/google_cloud_computing_platform/)

## Available Ruleset

| Rule           | Description                                                                                                                                                         |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GCP CIS 1.1    | Ensure that corporate login credentials are used                                                                                                                    |
| GCP CIS 1.5    | Ensure that Service Account has no Admin privileges                                                                                                                 |
| GCP CIS 1.6    | Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level                                             |
| GCP CIS 1.8    | Ensure that Separation of duties is enforced while assigning service account related roles to users                                                                 |
| GCP CIS 1.12   | Ensure API keys are not created for a project                                                                                                                       |
| GCP CIS 1.13   | Ensure API keys are restricted to use by only specified Hosts and Apps                                                                                              |
| GCP CIS 1.15   | Ensure API keys are rotated every 90 days                                                                                                                           |
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
| GCP CIS 3.1    | Ensure that the default network does not exist in a project                                                                                                         |
| GCP CIS 3.2    | Ensure legacy networks do not exist for a project                                                                                                                   |
| GCP CIS 3.3    | Ensure that DNSSEC is enabled for Cloud DNS                                                                                                                         |
| GCP CIS 3.4    | Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC                                                                                         |
| GCP CIS 3.5    | Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC                                                                                        |
| GCP CIS 3.6    | Ensure that SSH access is restricted from the internet                                                                                                              |
| GCP CIS 3.7    | Ensure that RDP access is restricted from the internet                                                                                                              |
| GCP CIS 3.8    | Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network                                                                                              |
| GCP CIS 3.9    | Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites                                                                             |
| GCP CIS 3.10   | Ensure Firewall Rules for instances behind Identity Aware Proxy (IAP) only allow the traffic from Google Cloud Loadbalancer (GCLB) Health Check and Proxy Addresses |
| GCP CIS 4.1    | Ensure that instances are not configured to use the default service account                                                                                         |
| GCP CIS 4.2    | Ensure that instances are not configured to use the default service account with full access to all Cloud APIs                                                      |
| GCP CIS 4.3    | Ensure "Block Project-wide SSH keys" is enabled for VM instances                                                                                                    |
| GCP CIS 4.5    | Ensure 'Enable connecting to serial ports' is not enabled for VM Instance                                                                                           |
| GCP CIS 4.6    | Ensure that IP forwarding is not enabled on Instances                                                                                                               |
| GCP CIS 4.7    | Ensure VM disks for critical VMs are encrypted with Customer-Supplied Encryption Keys (CSEK)                                                                        |
| GCP CIS 4.8    | Ensure Compute instances are launched with Shielded VM enabled                                                                                                      |
| GCP CIS 4.9    | Ensure that Compute instances do not have public IP addresses                                                                                                       |
| GCP CIS 4.11   | Ensure that Compute instances have Confidential Computing enabled                                                                                                   |
| GCP CIS 5.2    | Ensure that Cloud Storage buckets have uniform bucket-level access enabled                                                                                          |
| GCP CIS 6.1.2  | Ensure 'skip_show_database' database flag for Cloud SQL Mysql instance is set to 'on'                                                                               |
| GCP CIS 6.1.3  | Ensure that the 'local_infile' database flag for a Cloud SQL Mysql instance is set to 'off'                                                                         |
| GCP CIS 6.2.1  | Ensure that the 'log_checkpoints' database flag for Cloud SQL PostgreSQL instance is set to 'on'                                                                    |
| GCP CIS 6.2.2  | Ensure 'log_error_verbosity' database flag for Cloud SQL PostgreSQL instance is set to 'DEFAULT' or stricter                                                        |
| GCP CIS 6.2.3  | Ensure that the 'log_connections' database flag for Cloud SQL PostgreSQL instance is set to 'on'                                                                    |
| GCP CIS 6.2.4  | Ensure that the 'log_disconnections' database flag for Cloud SQL PostgreSQL instance is set to 'on'                                                                 |
| GCP CIS 6.2.5  | Ensure 'log_duration' database flag for Cloud SQL PostgreSQL instance is set to 'on'                                                                                |
| GCP CIS 6.2.6  | Ensure that the 'log_lock_waits' database flag for Cloud SQL PostgreSQL instance is set to 'on'                                                                     |
| GCP CIS 6.2.7  | Ensure 'log_statement' database flag for Cloud SQL PostgreSQL instance is set appropriately                                                                         |
| GCP CIS 6.2.8  | Ensure 'log_hostname' database flag for Cloud SQL PostgreSQL instance is set appropriately                                                                          |
| GCP CIS 6.2.9  | Ensure 'log_parser_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'                                                                           |
| GCP CIS 6.2.10 | Ensure 'log_planner_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'                                                                          |
| GCP CIS 6.2.11 | Ensure 'log_executor_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'                                                                         |
| GCP CIS 6.2.12 | Ensure 'log_statement_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'                                                                        |
| GCP CIS 6.2.13 | Ensure that the 'log_min_messages' database flag for Cloud SQL PostgreSQL instance is set appropriately                                                             |
| GCP CIS 6.2.14 | Ensure 'log_min_error_statement' database flag for Cloud SQL PostgreSQL instance is set to 'Error' or stricter                                                      |
| GCP CIS 6.2.15 | Ensure that the 'log_temp_files' database flag for Cloud SQL PostgreSQL instance is set to '0' (on)                                                                 |
| GCP CIS 6.2.16 | Ensure that the 'log_min_duration_statement' database flag for Cloud SQL PostgreSQL instance is set to '-1' (disabled)                                              |
| GCP CIS 6.3.1  | Ensure 'external scripts enabled' database flag for Cloud SQL SQL Server instance is set to 'off'                                                                   |
| GCP CIS 6.3.2  | Ensure that the 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off'                                                       |
| GCP CIS 6.3.3  | Ensure 'user connections' database flag for Cloud SQL SQL Server instance is set as appropriate                                                                     |
| GCP CIS 6.3.4  | Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured                                                                             |
| GCP CIS 6.3.5  | Ensure 'remote access' database flag for Cloud SQL SQL Server instance is set to 'off'                                                                              |
| GCP CIS 6.3.6  | Ensure '3625 (trace flag)' database flag for Cloud SQL SQL Server instance is set to 'off'                                                                          |
| GCP CIS 6.3.7  | Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is set to 'off'                                          |
| GCP CIS 6.4    | Ensure that the Cloud SQL database instance requires all incoming connections to use SSL                                                                            |
| GCP CIS 6.5    | Ensure that Cloud SQL database instances are not open to the world                                                                                                  |
| GCP CIS 6.6    | Ensure that Cloud SQL database instances do not have public IPs                                                                                                     |
| GCP CIS 6.7    | Ensure that Cloud SQL database instances are configured with automated backups                                                                                      |
