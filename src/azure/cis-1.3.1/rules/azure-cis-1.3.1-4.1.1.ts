export default {
  id: 'azure-cis-1.3.1-4.1.1',  
  title: 'Azure CIS 4.1.1 Ensure that \'Auditing\' is set to \'On\'',
  
  description: 'Enable auditing on SQL Servers.',
  
  audit: `**From Azure Console:**
  
  1. Go to SQL servers
  2. For each server instance
  3. Click on Auditing
  4. Ensure that Auditing is set to On
  
  **Using Azure PowerShell:**  
  Get the list of all SQL Servers
  
    Get-AzureRmSqlServer
    
  For each Server
  
    Get-AzureRmSqlServerAuditing -ResourceGroupName <resource group name> -ServerName <server name>
    
  Ensure that AuditState is set to Enabled.`,
  
  rationale: `The Azure platform allows a SQL server to be created as a service. Enabling auditing at the
  server level ensures that all existing and newly created databases on the SQL server
  instance are audited. Auditing policy applied on the SQL database does not override
  auditing policy and settings applied on the particular SQL server where the database is
  hosted.
  Auditing tracks database events and writes them to an audit log in the Azure storage
  account. It also helps to maintain regulatory compliance, understand database activity, and
  gain insight into discrepancies and anomalies that could indicate business concerns or
  suspected security violations.`,
  
  remediation: `**From Azure Console:**
  
  1. Go to SQL servers
  2. For each server instance
  3. Click on Auditing
  4. Set Auditing to On
  
  **Using Azure PowerShell:**  
  Get the list of all SQL Servers
  
    Get-AzureRmSqlServer
    
  For each Server, enable auditing.
  
    Set-AzureRmSqlServerAuditingPolicy -ResourceGroupName <resource group name> 
    -ServerName <server name> -AuditType <audit type> -StorageAccountName <storageaccount name>`,
  
  references: [
    'https://docs.microsoft.com/en-us/azure/security-center/security-center-enable-auditing-on-sql-servers',
    'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/get-azurermsqlserverauditing?view=azurermps-5.2.0',
    'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/set-azurermsqlserverauditingpolicy?view=azurermps-5.2.0',
    'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-auditing',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-4-enable-logging-for-azure-resources',
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
      equal: 'Enabled',
    }
  },
}
