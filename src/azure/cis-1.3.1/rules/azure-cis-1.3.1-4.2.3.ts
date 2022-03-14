export default {
  id: 'azure-cis-1.3.1-4.2.3',  
  title: 'Azure CIS 4.2.3 Ensure that VA setting Periodic Recurring Scans is enabled on a SQL server',
  
  description: `Enable Vulnerability Assessment (VA) Periodic recurring scans for critical SQL servers and corresponding SQL databases.`,
  
  audit: `**From Azure Console:**
  
  1. Go to SQL servers
  2. Select a server instance
  3. Click on Security Center
  4. Ensure that Azure Defender for SQL is set to Enabled
  5. In Section Vulnerability Assessment Settings, Ensure Storage Accounts is configured.
  6. In Section Vulnerability Assessment Settings, Ensure Periodic recurring scans is set to On.
  
  **Using Azure PowerShell:**  
  Get the list of all SQL Servers
  
    Get-AzSqlServer
    
  For each Server
  
    Get-AzSqlServerVulnerabilityAssessmentSetting -ResourceGroupName <resource
    group name> -ServerName <server name>
    
  Ensure that value for parameter RecurringScansInterval is not set to None.
  Sample Output:
  
    ResourceGroupName : ResourceGroup01
    ServerName : Server01
    StorageAccountName : mystorage
    ScanResultsContainerName : vulnerability-assessment
    RecurringScansInterval : weekly
    EmailSubscriptionAdmins : False
    NotificationEmail : {}`,
  
  rationale: `VA setting 'Periodic recurring scans' schedules periodic (weekly) vulnerability scanning for
  the SQL server and corresponding Databases. Periodic and regular vulnerability scanning
  provides risk visibility based on updated known vulnerability signatures and best
  practices.`,
  
  remediation: `**From Azure Console:**
  
  1. Go to SQL servers
  2. For each server instance
  3. Click on Security Center
  4. In Section Vulnerability Assessment Settings, set Storage Account if not
  already
  5. Toggle 'Periodic recurring scans' to ON.
  6. Click Save
  
  **Using Azure PowerShell:**  
  If not already, Enable Advanced Data Security for a SQL Server:
  
    Set-AZSqlServerThreatDetectionPolicy -ResourceGroupName <resource group name>
    -ServerName <server name> -EmailAdmins $True
    
  To enable ADS-VA service with 'Periodic recurring scans'
  
    Update-AzSqlServerVulnerabilityAssessmentSetting
      -ResourceGroupName "<resource group name>"
      -ServerName "<Server Name>"
      -StorageAccountName "<Storage Name from same subscription and same Location"
      -ScanResultsContainerName "vulnerability-assessment"
      -RecurringScansInterval Weekly
      -EmailSubscriptionAdmins $true
      -NotificationEmail @("mail1@mail.com" , "mail2@mail.com")`,
  
  references: [
    'https://docs.microsoft.com/en-us/azure/sql-database/sql-vulnerability-assessment',
    'https://docs.microsoft.com/en-us/rest/api/sql/servervulnerabilityassessments/listbyserver',
    'https://docs.microsoft.com/en-in/powershell/module/Az.Sql/Update-AzSqlServerVulnerabilityAssessmentSetting?view=azps-2.6.0',
    'https://docs.microsoft.com/en-in/powershell/module/Az.Sql/Get-AzSqlServerVulnerabilityAssessmentSetting?view=azps-2.6.0',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-posture-vulnerability-management#pv-6-perform-software-vulnerability-assessments',
  ],  
  gql: `{
    queryazureSqlServer {
      id
      __typename       
      vulnerabilityAssessments {
        storageContainerPath
      }
    }
  }`,
  resource: 'queryazureSqlServer[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.vulnerabilityAssessments',
        isEmpty: false,
      },
      {
        path: '@.vulnerabilityAssessments',
        array_any: {
          path: '[*].storageContainerPath',
          notIn: [null, ''],
        }
      },
    ],
  },
}
