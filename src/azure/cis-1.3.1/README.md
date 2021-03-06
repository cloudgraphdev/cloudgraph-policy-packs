# CIS Microsoft Azure Foundations Benchmark 1.3.1

Policy Pack based on the Azure Foundations 1.3.1 benchmark provided by the [Center for Internet Security (CIS)](https://www.cisecurity.org/benchmark/azure/)

## First Steps

1. Install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start).
2. Set up the [Azure Provider](https://www.npmjs.com/package/@cloudgraph/cg-provider-azure) for CG with the `cg init azure` command.
3. Add Policy Pack for CIS Microsoft Azure Foundations benchmark using `cg policy add azure-cis-1.3.1` command.
4. Execute the ruleset using the scan command `cg scan azure`.
5. Query the findings using the different options:

   5a. Querying findings by provider:

   ```graphql
   query {
     queryazureFindings {
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
     queryazureCISFindings {
       id
       resourceId
       result
     }
   }
   ```

   5c. Querying findings by resource:

   ```graphql
   query {
     queryazureSecurityPricing {
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

| Rule           | Description                                                                                                                   |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Azure CIS 1.1  | Ensure that multi-factor authentication is enabled for all privileged users (Manual)                                          |
| Azure CIS 1.2  | Ensure that multi-factor authentication is enabled for all non-privileged users (Manual)                                      |
| Azure CIS 1.3  | Ensure guest users are reviewed on a monthly basis                                                                            |
| Azure CIS 1.4  | Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is 'Disabled' (Manual)                |
| Azure CIS 1.5  | Ensure that 'Number of methods required to reset' is set to '2' (Manual)                                                      |
| Azure CIS 1.6  | Ensure that 'Number of days before users are asked to re-confirm their authentication information' is not set to "0" (Manual) |
| Azure CIS 1.7  | Ensure that 'Notify users on password resets?' is set to 'Yes' (Manual)                                                       |
| Azure CIS 1.8  | Ensure that 'Notify all admins when other admins reset their password?' is set to 'Yes' (Manual)                              |
| Azure CIS 1.9  | Ensure that 'Users can consent to apps accessing company data on their behalf' is set to 'No' (Manual)                        |
| Azure CIS 1.10 | Ensure that 'Users can add gallery apps to their Access Panel' is set to 'No' (Manual)                                        |
| Azure CIS 1.11 | Ensure that 'Users can register applications' is set to 'No' (Manual)                                                         |
| Azure CIS 1.12 | Ensure that 'Guest user permissions are limited' is set to 'Yes' (Manual)                                                     |
| Azure CIS 1.13 | Ensure that 'Members can invite' is set to 'No' (Manual)                                                                      |
| Azure CIS 1.14 | Ensure that 'Guests can invite' is set to 'No' (Manual)                                                                       |
| Azure CIS 1.15 | Ensure that 'Restrict access to Azure AD administration portal' is set to 'Yes' (Manual)                                      |
| Azure CIS 1.16 | Ensure that 'Restrict user ability to access groups features in the Access Pane' is set to 'No' (Manual)                      |
| Azure CIS 1.17 | Ensure that 'Users can create security groups in Azure Portals' is set to 'No' (Manual)                                       |
| Azure CIS 1.18 | Ensure that 'Owners can manage group membership requests in the Access Panel' is set to 'No' (Manual)                         |
| Azure CIS 1.19 | Ensure that 'Users can create Microsoft 365 groups in Azure Portals' is set to 'No' (Manual)                                  |
| Azure CIS 1.20 | Ensure that 'Require Multi-Factor Auth to join devices' is set to 'Yes' (Manual)                                              |
| Azure CIS 1.21 | Ensure that no custom subscription owner roles are created                                                                    |
| Azure CIS 1.22 | Ensure Security Defaults is enabled on Azure Active Directory                                                                 |
| Azure CIS 1.23 | Ensure Custom Role is assigned for Administering Resource Locks (Manual)                                                      |
| Azure CIS 2.1  | Ensure that Azure Defender is set to On for Servers                                                                           |
| Azure CIS 2.2  | Ensure that Azure Defender is set to On for App Service                                                                       |
| Azure CIS 2.3  | Ensure that Azure Defender is set to On for Azure SQL database servers                                                        |
| Azure CIS 2.4  | Ensure that Azure Defender is set to On for SQL servers on machines                                                           |
| Azure CIS 2.5  | Ensure that Azure Defender is set to On for Storage                                                                           |
| Azure CIS 2.6  | Ensure that Azure Defender is set to On for Kubernetes                                                                        |
| Azure CIS 2.7  | Ensure that Azure Defender is set to On for Container Registries                                                              |
| Azure CIS 2.8  | Ensure that Azure Defender is set to On for Key Vault                                                                         |
| Azure CIS 2.9  | Ensure that Windows Defender ATP (WDATP) integration with Security Center is selected                                         |
| Azure CIS 2.10 | Ensure that Microsoft Cloud App Security (MCAS) integration with Security Center is selected                                  |
| Azure CIS 2.11 | Ensure that 'Automatic provisioning of monitoring agent' is set to 'On'                                                       |
| Azure CIS 2.12 | Ensure any of the ASC Default policy setting is not set to "Disabled"                                                         |
| Azure CIS 2.13 | Ensure 'Additional email addresses' is configured with a security contact email                                               |
| Azure CIS 2.14 | Ensure that 'Notify about alerts with the following severity' is set to 'High'                                                |
| Azure CIS 2.15 | Ensure that "All users with the following roles" is set to "Owner"                                                            |
| Azure CIS 3.1  | Ensure that 'Secure transfer required' is set to 'Enabled'                                                                    |
| Azure CIS 3.2  | Ensure that storage account access keys are periodically regenerated (Manual)                                                 |
| Azure CIS 3.3  | Ensure Storage logging is enabled for Queue service for read, write, and delete requests                                      |
| Azure CIS 3.4  | Ensure sure that shared access signature tokens expire within an hour (Manual)                                                |
| Azure CIS 3.5  | Ensure that 'Public access level' is set to Private for blob containers                                                       |
| Azure CIS 3.6  | Ensure default network access rule for Storage Accounts is set to deny                                                        |
| Azure CIS 3.7  | Ensure 'Trusted Microsoft Services' is enabled for Storage Account access (Manual)                                            |
| Azure CIS 3.8  | Ensure soft delete is enabled for Azure Storage                                                                               |
| Azure CIS 3.9  | Ensure storage for critical data are encrypted with Customer Managed Key                                                      |
| Azure CIS 3.10 | Ensure Storage logging is enabled for Blob service for read, write, and delete requests (Manual)                              |
| Azure CIS 3.11 | Ensure Storage logging is enabled for Table service for read, write, and delete requests (Manual)                             |
| Azure CIS 4.1.1| Ensure that 'Auditing' is set to 'On'                                                                                         |
| Azure CIS 4.1.2| Ensure that 'Data encryption' is set to 'On' on a SQL Database                                                                |
| Azure CIS 4.1.3| Ensure that 'Auditing' Retention is 'greater than 90 days'                                                                    |
| Azure CIS 4.2.1| Ensure that Advanced Threat Protection (ATP) on a SQL server is set to 'Enabled'                                              |
| Azure CIS 4.2.2| Ensure that Vulnerability Assessment (VA) is enabled on a SQL server by setting a Storage Account                             |
| Azure CIS 4.2.3| Ensure that VA setting Periodic Recurring Scans is enabled on a SQL server                                                    |
| Azure CIS 4.2.4| Ensure that VA setting Send scan reports to is configured for a SQL server                                                    |
| Azure CIS 4.2.5| Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server              |
| Azure CIS 4.3.1| Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server                                            |
| Azure CIS 4.3.2| Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server                                                 |
| Azure CIS 4.3.3| Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server                                       |
| Azure CIS 4.3.4| Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server                                       |
| Azure CIS 4.3.5| Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server                                    |
| Azure CIS 4.3.6| Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server                                 |
| Azure CIS 4.3.7| Ensure server parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server                            |
| Azure CIS 4.3.8| Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled                                            |
| Azure CIS 4.4  | Ensure that Azure Active Directory Admin is configured                                                                        |
| Azure CIS 4.5  | Ensure SQL server's TDE protector is encrypted with Customer-managed key                                                      |
| Azure CIS 5.1.1| Ensure that a 'Diagnostics Setting' exists (Manual)                                                                           |
| Azure CIS 5.1.2| Ensure Diagnostic Setting captures appropriate categories                                                                     |
| Azure CIS 5.1.3| Ensure the storage container storing the activity logs is not publicly accessible                                             |
| Azure CIS 5.1.4| Ensure the storage account containing the container with activity logs is encrypted with BYOK (Use Your Own Key)              |
| Azure CIS 5.1.5| Ensure that logging for Azure KeyVault is 'Enabled' (Manual)                                                                  |
| Azure CIS 5.2.1| Ensure that Activity Log Alert exists for Create Policy Assignment                                                            |
| Azure CIS 5.2.2| Ensure that Activity Log Alert exists for Delete Policy Assignment                                                            |
| Azure CIS 5.2.3| Ensure that Activity Log Alert exists for Create or Update Network Security Group                                             |
| Azure CIS 5.2.4| Ensure that Activity Log Alert exists for Delete Network Security Group                                                       |
| Azure CIS 5.2.5| Ensure that Activity Log Alert exists for Create or Update Network Security Group Rule                                        |
| Azure CIS 5.2.6| Ensure that Activity Log Alert exists for the Delete Network Security Group Rule                                              |
| Azure CIS 5.2.7| Ensure that Activity Log Alert exists for Create or Update Security Solution                                                  |
| Azure CIS 5.2.8| Ensure that Activity Log Alert exists for Delete Security Solution                                                            |
| Azure CIS 5.2.9| Ensure that Activity Log Alert exists for Create or Update or Delete SQL Server Firewall Rule                                 |
| Azure CIS 5.3  | Ensure that Diagnostic Logs are enabled for all services which support it (Manual)                                            |
| Azure CIS 6.1  | Ensure that RDP access is restricted from the internet                                                                        |
| Azure CIS 6.2  | Ensure that SSH access is restricted from the internet                                                                        |
| Azure CIS 6.3  | Ensure no SQL Databases allow ingress 0.0.0.0/0 (ANY IP)                                                                      |
| Azure CIS 6.4  | Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'                                        |
| Azure CIS 6.5  | Ensure that Network Watcher is 'Enabled' (Manual)                                                                             |
| Azure CIS 6.6  | Ensure that UDP Services are restricted from the Internet                                                                     |
| Azure CIS 7.1  | Ensure Virtual Machines are utilizing Managed Disks                                                                           |
| Azure CIS 7.2  | Ensure that 'OS and Data' disks are encrypted with CMK                                                                        |
| Azure CIS 7.3  | Ensure that 'Unattached disks' are encrypted with CMK                                                                         |
| Azure CIS 7.4  | Ensure that only approved extensions are installed (Manual)                                                                   |
| Azure CIS 7.5  | Ensure that the latest OS Patches for all Virtual Machines are applied (Manual)                                               |
| Azure CIS 7.6  | Ensure that the endpoint protection for all Virtual Machines is installed (Manual)                                            |
| Azure CIS 7.7  | Ensure that VHD's are encrypted                                                                                               |
| Azure CIS 8.1  | Ensure that the expiration date is set on all keys                                                                            |
| Azure CIS 8.2  | Ensure that the expiration date is set on all Secrets                                                                         |
| Azure CIS 8.3  | Ensure that Resource Locks are set for mission critical Azure resources (Manual)                                              |
| Azure CIS 8.4  | Ensure the key vault is recoverable                                                                                           |
| Azure CIS 8.5  | Enable role-based access control (RBAC) within Azure Kubernetes Services                                                      |
| Azure CIS 9.1  | Ensure App Service Authentication is set on Azure App Service                                                                 |
| Azure CIS 9.2  | Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service                                                       |
| Azure CIS 9.3  | Ensure web app is using the latest version of TLS encryption                                                                  |
| Azure CIS 9.4  | Ensure the web app has 'Client Certificates (Incoming client certificates)' set to 'On'                                       |
| Azure CIS 9.5  | Ensure that Register with Azure Active Directory is enabled on App Service                                                    |
| Azure CIS 9.6  | Ensure that 'PHP version' is the latest, if used to run the web app (Manual)                                                  |
| Azure CIS 9.7  | Ensure that 'Python version' is the latest, if used to run the web app (Manual)                                               |
| Azure CIS 9.8  | Ensure that 'Java version' is the latest, if used to run the web app (Manual)                                                 |
| Azure CIS 9.9  | Ensure that 'HTTP Version' is the latest, if used to run the web app                                                          |
| Azure CIS 9.11 | Ensure Azure Keyvaults are used to store secrets (Manual)                                                                     |
