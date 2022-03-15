export default {
  id: 'azure-cis-1.3.1-4.2.1',  
  title: 'Azure CIS 4.2.1 Ensure that Advanced Threat Protection (ATP) on a SQL server is set to \'Enabled\'',
  
  description: `Enable "Azure Defender for SQL" on critical SQL Servers.`,
  
  audit: `**From Azure Console:**
  
  1. Go to SQL servers
  2. For each server instance
  3. Click on Azure Defender for SQL
  4. Ensure that Azure Defender for SQL is set to On
  
  **Using Azure PowerShell:**  
  Get the list of all SQL Servers
  
    Get-AzSqlServer
    
  For each Server
  
    Get-AzSqlServerThreatDetectionPolicy -ResourceGroupName <resource group name>
    -ServerName <server name>
    
  Ensure that ThreatDetectionState is set to Enabled.`,
  
  rationale: `Azure Defender for SQL is a unified package for advanced SQL security capabilities. Azure
  Defender is available for Azure SQL Database, Azure SQL Managed Instance, and Azure
  Synapse Analytics. It includes functionality for discovering and classifying sensitive data,
  surfacing and mitigating potential database vulnerabilities, and detecting anomalous
  activities that could indicate a threat to your database. It provides a single go-to location for
  enabling and managing these capabilities.`,
  
  remediation: `**From Azure Console:**
  
  1. Go to SQL servers
  2. For each server instance
  3. Click on Azure Defender for SQL
  4. Set Azure Defender for SQL to On
  
  **Using Azure PowerShell:**  
  Enable Advanced Data Security for a SQL Server:
  
    Set-AzSqlServerThreatDetectionPolicy -ResourceGroupName <resource group name>
    -ServerName <server name> -EmailAdmins $True
    
  Note:
  - Enabling 'Azure Defender for SQL' from the Azure portal enables Threat Detection
  - Using Powershell command Set-AzSqlServerThreatDetectionPolicy enables Azure Defender for SQL for a SQL server`,
  
  references: [
    'https://docs.microsoft.com/en-us/azure/azure-sql/database/azure-defender-for-sql',
    'https://docs.microsoft.com/cs-cz/powershell/module/azurerm.sql/get-azurermsqlserverthreatdetectionpolicy?view=azurermps-5.2.0',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-data-protection#dp-3-monitor-for-unauthorized-transfer-of-sensitive-data'
  ],  
  gql: `{
    queryazureSqlServer {
      id
      __typename
      serverSecurityAlertPolicies {
        state
      }
    }
  }`,
  resource: 'queryazureSqlServer[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.serverSecurityAlertPolicies',
        isEmpty: false,
      },
      {
        path: '@.serverSecurityAlertPolicies',
        array_any: {
          path: '[*].state',
          equal: 'Enabled',
        }
      },
    ],
  },
}
