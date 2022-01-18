# CIS Google Cloud Platform Foundations 1.2.0

Policy Pack based on the GCP Foundations 1.2.0 benchmark provided by the [Center for Internet Security (CIS)](https://www.cisecurity.org/benchmark/google_cloud_computing_platform/)

## Available Ruleset

| Rule        | Description                                                                  |
| ----------- | ---------------------------------------------------------------------------- |
| GCP CIS 2.9 | Ensure that the log metric filter and alerts exist for VPC network changes   |
| GCP CIS 2.10 | Ensure that the log metric filter and alerts exist for Cloud Storage IAM permission changes |
| GCP CIS 2.11 | Ensure that the log metric filter and alerts exist for SQL instance configuration changes   |
| GCP CIS 2.12 | Ensure that Cloud DNS logging is enabled for all VPC networks               |
| GCP CIS 3.1 | Ensure that the default network does not exist in a project                  |
| GCP CIS 3.2 | Ensure legacy networks do not exist for a project                            |
| GCP CIS 3.3 | Ensure that DNSSEC is enabled for Cloud DNS                                  |
| GCP CIS 3.4 | Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC  |
| GCP CIS 3.5 | Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC |
| GCP CIS 3.6 | Ensure that SSH access is restricted from the internet                       |
| GCP CIS 3.7 | Ensure that RDP access is restricted from the internet                       |
| GCP CIS 3.8 | Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network       |
| GCP CIS 3.10 | Ensure Firewall Rules for instances behind Identity Aware Proxy (IAP) only allow the traffic from Google Cloud Loadbalancer (GCLB) Health Check and Proxy Addresses |
| GCP CIS 4.8 | Ensure Compute instances are launched with Shielded VM enabled               |
| GCP CIS 4.9 | Ensure that Compute instances do not have public IP addresses                |
| GCP CIS 4.11 | Ensure that Compute instances have Confidential Computing enabled           |