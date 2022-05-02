export default {
  id: 'azure-cis-1.3.1-4.4',  
  title: 'Azure CIS 4.4 Ensure that Azure Active Directory Admin is configured',
  
  description: 'Use Azure Active Directory Authentication for authentication with SQL Database.',
  
  audit: `**From Azure Console**
  
  1. Go to SQL servers
  2. For each SQL server, click on Active Directory admin
  3. Ensure that an AD account has been populated for field Active Directory admin
  
  **Using Azure PowerShell**  
  
      Get the list of all SQL Servers Get-AzureRmSqlServer
  
  For each Server  
  
      Get-AzureRmSqlServerActiveDirectoryAdministrator -ResourceGroupName <resource group name> -ServerName <server name>
  
  Ensure Output shows DisplayName set to AD account.`,
  
  rationale: `Azure Active Directory authentication is a mechanism to connect to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in Azure Active Directory (Azure AD). With Azure AD authentication, identities of database users and other Microsoft services can be managed in one central location. Central ID management provides a single place to manage database users and simplifies permission management.
  
  - It provides an alternative to SQL Server authentication.
  - Helps stop the proliferation of user identities across database servers.
  - Allows password rotation in a single place.
  - Customers can manage database permissions using external (AAD) groups.
  - It can eliminate storing passwords by enabling integrated Windows authentication and other forms of authentication supported by Azure Active Directory.
  - Azure AD authentication uses contained database users to authenticate identities at the database level.
  - Azure AD supports token-based authentication for applications connecting to SQL Database.
  - Azure AD authentication supports ADFS (domain federation) or native user/password authentication for a local Azure Active Directory without domain synchronization.
  - Azure AD supports connections from SQL Server Management Studio that use Active Directory Universal Authentication, which includes Multi-Factor Authentication (MFA). MFA includes strong authentication with a range of easy verification options — phone call, text message, smart cards with pin, or mobile app notification.`,
  
  remediation: `**From Azure Console**
  
  1. Go to SQL servers
  2. For each SQL server, click on Active Directory admin
  3. Click on Set admin
  4. Select an admin
  5. Click Save
  
  **Using Azure PowerShell**  
  For each Server, set AD Admin
  
      Set-AzureRmSqlServerActiveDirectoryAdministrator -ResourceGroupName <resource group name> -ServerName <server name> -DisplayName "<Display name of AD account to set as DB administrator>"
  
  **From Azure Command Line Interface 2.0**  
  Get ObjectID of user
  
      az ad user list --query "[?mail==<emailId of user>].{mail:mail, userPrincipalName:userPrincipalName, objectId:objectId}"
  
  For each Server, set AD Admin
  
      az sql server ad-admin create --resource-group <resource group name> --server <server name> --display-name <display name> --object-id <object id of user>`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-aad-authentication-configure',
      'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-aad-authentication',
      'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/get-azurermsqlserveractivedirectoryadministrator?view=azurermps-5.2.0',
      'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/set-azurermsqlserveractivedirectoryadministrator?view=azurermps-5.2.0',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-identity-management#im-1-standardize-azure-active-directory-as-the-central-identity-and-authentication-system',
  ],  
  gql: `{
    queryazureSqlServer {
      id
      __typename
      adAdministrators {
        id
      }
    }
  }`,
  resource: 'queryazureSqlServer[*]',
  severity: 'medium',
  conditions: {
    path: '@.adAdministrators',
    isEmpty: false,
  },
}
