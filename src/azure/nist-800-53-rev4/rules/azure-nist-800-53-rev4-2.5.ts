export default {
  id: 'azure-nist-800-53-rev4-2.5',  
  title: 'Azure NIST 2.5 SQL Server auditing should be enabled',
  
  description: 'The Azure platform allows a SQL server to be created as a service. Enabling auditing at the server level ensures that all existing and newly created databases on the SQL server instance are audited. Auditing policy applied on the SQL database does not override auditing policy and settings applied on the particular SQL server where the database is hosted.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**From Azure Console**
  
  - Navigate to [SQL Servers](https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Sql%2Fservers).
  - Select the SQL server.
  - In the left navigation in the Security section, select Auditing.
  - Set Auditing to On.
  
  **Using PowerShell:**
  
  - To enable auditing for SQL Server, get a list of all SQL servers:
  
          Get-AzureRmSqlServer
  
  - Enable auditing for each server:
  
          Set-AzureRmSqlServerAuditingPolicy -ResourceGroupName <resource group name> -ServerName <server name> -AuditType <audit type> -StorageAccountName <storage account name>`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/security-center/security-center-sql-service-recommendations',
      'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/get-azurermsqlserverauditing?view=azurermps-6.13.0&viewFallbackFrom=azurermps-5.2.0',
      'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/set-azurermsqlserverauditingpolicy?view=azurermps-6.13.0&viewFallbackFrom=azurermps-5.2.0',
      'https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview',
  ],
  gql: `{
    queryazureSqlServer {
      id
      __typename
      serverBlobAuditingPolicies {
        state
      }
    }
  }`,
  resource: 'queryazureSqlServer[*]',
  severity: 'medium',
  conditions: {
    path: '@.serverBlobAuditingPolicies',
    array_any: {
      path: '[*].state', 
      equal: 'Enabled' 
    },
  },
}
