export default {
  id: 'azure-cis-1.3.1-4.1.3',  
  title: 'Azure CIS 4.1.3 Ensure that \'Auditing\' Retention is \'greater than 90 days\'',
  
  description: 'SQL Server Audit Retention should be configured to be greater than 90 days.',
  
  audit: `**From Azure Console:**
  
  1. Go to SQL servers
  2. For each server instance
  3. Click on Auditing
  4. Select Storage Details
  5. Ensure Retention (days) setting greater than 90 days
  
  **Using Azure PowerShell:**  
  Get the list of all SQL Servers
  
    Get-AzureRmSqlServer
    
  For each Server
  
    Get-AzureRmSqlServerAuditing -ResourceGroupName <resource group name> -ServerName <server name>
    
  Ensure that RetentionInDays is set to more than or equal to 90`,
  
  rationale: `Audit Logs can be used to check for anomalies and give insight into suspected breaches or
  misuse of information and access.`,
  
  remediation: `**From Azure Console:**
  
  1. Go to SQL servers
  2. For each server instance
  3. Click on Auditing
  4. Select Storage Details
  5. Set Retention (days) setting greater than 90 days
  6. Select OK
  7. Select Save
  
  **Using Azure PowerShell:**  
  For each Server, set retention policy for more than or equal to 90 days
  
    set-AzureRmSqlServerAuditing -ResourceGroupName <resource group name> 
    -ServerName <server name> -RetentionInDays <Number of Days to retain the audit logs, should be 90days minimum>`,
  
  references: [
    'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-auditing',
    'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/get-azurermsqlserverauditing?view=azurermps-5.2.0',
    'https://docs.microsoft.com/en-us/powershell/module/azurerm.sql/set-azurermsqlserverauditing?view=azurermps-5.2.0',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-6-configure-log-storage-retention',
  ],
  gql: `{
    queryazureSqlServer {
      id
      __typename
      serverBlobAuditingPolicies {
        retentionDays
      }
    }
  }`,
  resource: 'queryazureSqlServer[*]',
  severity: 'medium',
  conditions: {
    path: '@.serverBlobAuditingPolicies',
    array_any: {
      path: '[*].retentionDays',
      greaterThanInclusive: 90,
    }
  },
}
