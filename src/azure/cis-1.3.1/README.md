# CIS Microsoft Azure Foundations Benchmark 1.3.1

Policy Pack based on the Azure Foundations 1.3.1 benchmark provided by the [Center for Internet Security (CIS)](https://www.cisecurity.org/benchmark/azure/)

## First Steps

1. Install [Cloud Graph CLI](https://docs.cloudgraph.dev/quick-start).
2. Set up the [Azure Provider](https://www.npmjs.com/package/@cloudgraph/cg-provider-azure) for CG with the `cg init azure` command.
3. Add Policy Pack for CIS Microsoft Azure Foundations benchmark using `cg policy add azure-cis-1.2.0` command.
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

| Rule           | Description                                                                                                                                      |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Azure CIS 1.1  | Ensure that multi-factor authentication is enabled for all privileged users (Manual)                                                             |
| Azure CIS 1.2  | Ensure that multi-factor authentication is enabled for all non-privileged users (Manual)                                                         |
| Azure CIS 1.3  | Ensure guest users are reviewed on a monthly basis                                                                                               |
| Azure CIS 1.4  | Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is 'Disabled' (Manual)                                   |
| Azure CIS 1.5  | Ensure that 'Number of methods required to reset' is set to '2' (Manual)                                                                         |
| Azure CIS 1.6  | Ensure that 'Number of days before users are asked to re-confirm their authentication information' is not set to "0" (Manual)                    |
| Azure CIS 1.7  | Ensure that 'Notify users on password resets?' is set to 'Yes' (Manual)                                                                          |
| Azure CIS 1.8  | Ensure that 'Notify all admins when other admins reset their password?' is set to 'Yes' (Manual)                                                 |
| Azure CIS 1.9  | Ensure that 'Users can consent to apps accessing company data on their behalf' is set to 'No' (Manual)                                           |
| Azure CIS 1.10 | Ensure that 'Users can add gallery apps to their Access Panel' is set to 'No' (Manual)                                                           |
| Azure CIS 1.11 | Ensure that 'Users can register applications' is set to 'No' (Manual)                                                                            |
| Azure CIS 1.12 | Ensure that 'Guest user permissions are limited' is set to 'Yes' (Manual)                                                                        |
| Azure CIS 1.13 | Ensure that 'Members can invite' is set to 'No' (Manual)                                                                                         |
| Azure CIS 1.14 | Ensure that 'Guests can invite' is set to 'No' (Manual)                                                                                          |
| Azure CIS 1.15 | Ensure that 'Restrict access to Azure AD administration portal' is set to 'Yes' (Manual)                                                         |
| Azure CIS 1.16 | Ensure that 'Restrict user ability to access groups features in the Access Pane' is set to 'No' (Manual)                                         |
| Azure CIS 1.17 | Ensure that 'Users can create security groups in Azure Portals' is set to 'No' (Manual)                                                          |
| Azure CIS 1.18 | Ensure that 'Owners can manage group membership requests in the Access Panel' is set to 'No' (Manual)                                            |
| Azure CIS 1.19 | Ensure that 'Users can create Microsoft 365 groups in Azure Portals' is set to 'No' (Manual)                                                     |
| Azure CIS 1.20 | Ensure that 'Require Multi-Factor Auth to join devices' is set to 'Yes' (Manual)                                                                 |
| Azure CIS 1.21 | Ensure that no custom subscription owner roles are created                                                                                       |
| Azure CIS 1.22 | Ensure Security Defaults is enabled on Azure Active Directory                                                                                    |
| Azure CIS 1.23 | Ensure Custom Role is assigned for Administering Resource Locks (Manual)                                                                         |
| Azure CIS 2.1  | Ensure that Azure Defender is set to On for Servers                                                                                              |
| Azure CIS 2.2  | Ensure that Azure Defender is set to On for App Service                                                                                          |
| Azure CIS 2.3  | Ensure that Azure Defender is set to On for Azure SQL database servers                                                                           |
| Azure CIS 2.4  | Ensure that Azure Defender is set to On for SQL servers on machines                                                                              |
| Azure CIS 2.5  | Ensure that Azure Defender is set to On for Storage                                                                                              |
| Azure CIS 2.6  | Ensure that Azure Defender is set to On for Kubernetes                                                                                           |
| Azure CIS 2.7  | Ensure that Azure Defender is set to On for Container Registries                                                                                 |
| Azure CIS 2.8  | Ensure that Azure Defender is set to On for Key Vault                                                                                            |
| Azure CIS 3.1  | Ensure that 'Secure transfer required' is set to 'Enabled'                                                                                       |
| Azure CIS 3.2  | Ensure that storage account access keys are periodically regenerated (Manual)                                                                    |
| Azure CIS 3.3  | Ensure Storage logging is enabled for Queue service for read, write, and delete requests (Manual)                                                |
| Azure CIS 3.4  | Ensure sure that shared access signature tokens expire within an hour (Manual)                                                                   |
| Azure CIS 3.5  | Ensure that 'Public access level' is set to Private for blob containers                                                                          |
| Azure CIS 3.6  | Ensure default network access rule for Storage Accounts is set to deny                                                                           |
| Azure CIS 3.7  | Ensure 'Trusted Microsoft Services' is enabled for Storage Account access (Manual)                                                               |
| Azure CIS 3.8  | Ensure soft delete is enabled for Azure Storage                                                                                                  |
| Azure CIS 3.9  | Ensure storage for critical data are encrypted with Customer Managed Key                                                                         |
| Azure CIS 3.10 | Ensure Storage logging is enabled for Blob service for read, write, and delete requests (Manual)                                                 |
| Azure CIS 3.11 | Ensure Storage logging is enabled for Table service for read, write, and delete requests (Manual)                                                |
