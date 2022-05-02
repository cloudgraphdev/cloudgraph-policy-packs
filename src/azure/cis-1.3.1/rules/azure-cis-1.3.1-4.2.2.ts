export default {
  id: 'azure-cis-1.3.1-4.2.2',  
  title: 'Azure CIS 4.2.2 Ensure that Vulnerability Assessment (VA) is enabled on a SQL server by setting a Storage Account',
  
  description: `Enable Vulnerability Assessment (VA) service scans for critical SQL servers and corresponding SQL databases.`,
  
  audit: `**From Azure Console:**
  
  1. Go to SQL servers
  2. Select a server instance
  3. Click on Security Center
  4. Ensure that Azure Defender for SQL is set to Enabled
  5. Select Configure next to Enabled at subscription-level
  6. In Section Vulnerability Assessment Settings, Ensure Storage Accounts is does not read Configure required settings.
  
  **Using Azure PowerShell:**  
  Get the list of all SQL Servers
  
    Get-AzSqlServer
    
  For each Server
  
    Get-AzSqlServerVulnerabilityAssessmentSetting -ResourceGroupName <resource
    group name> -ServerName <server name>
    
  Ensure that value for parameter StorageAccountName is not empty (blank).
  Sample Output:
  
    ResourceGroupName : ResourceGroup01
    ServerName : Server01
    StorageAccountName : mystorage
    ScanResultsContainerName : vulnerability-assessment
    RecurringScansInterval : None
    EmailSubscriptionAdmins : False
    NotificationEmail : {}`,
  
  rationale: `Enabling Azure Defender for SQL server does not enables Vulnerability Assessment
  capability for individual SQL databases unless storage account is set to store the scanning
  data and reports.
  The Vulnerability Assessment service scans databases for known security vulnerabilities
  and highlight deviations from best practices, such as misconfigurations, excessive
  permissions, and unprotected sensitive data. Results of the scan include actionable steps to
  resolve each issue and provide customized remediation scripts where applicable.
  Additionally an assessment report can be customized by setting an acceptable baseline for
  permission configurations, feature configurations, and database settings.`,
  
  remediation: `**From Azure Console:**
  
  1. Go to SQL servers
  2. Select a server instance
  3. Click on Security Center
  4. Select Configure next to Enabled at subscription-level
  5. In Section Vulnerability Assessment Settings, Click Storage Account
  6. Choose Storage Account (Existing or Create New). Click Ok
  7. Click Save
  
  **Using Azure PowerShell:**  
  If not already, Enable Azure Defender for a SQL:
  
    Set-AZSqlServerThreatDetectionPolicy -ResourceGroupName <resource group name>
    -ServerName <server name> -EmailAdmins $True
    
  To enable ADS-VA service by setting Storage Account
  
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
