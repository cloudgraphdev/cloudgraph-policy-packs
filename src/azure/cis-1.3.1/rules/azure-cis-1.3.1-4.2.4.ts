export default {
  id: 'azure-cis-1.3.1-4.2.4',  
  title: 'Azure CIS 4.2.4 Ensure that VA setting Send scan reports to is configured for a SQL server',
  
  description: `Configure 'Send scan reports to' with email ids of concerned data owners/stakeholders for a critical SQL servers.`,
  
  audit: `**From Azure Console:**
  
  1. Go to SQL servers
  2. Select a server instance 
  3. Click on Security Center
  4. Ensure that Azure Defender for SQL is set to Enabled
  5. Select Configure next to Enabled at subscription-level
  6. In Section Vulnerability Assessment Settings, Ensure Storage Accounts is Configured.
  7. In Section Vulnerability Assessment Settings, Ensure Send scan reports to is not empty.
  
  **Using Azure PowerShell:**  
  Get the list of all SQL Servers
  
    Get-AzSqlServer
    
  For each Server
  
    Get-AzSqlServerVulnerabilityAssessmentSetting -ResourceGroupName <resource
    group name> -ServerName <server name>
    
  Ensure that value for parameter NotificationEmail is not blank/empty {}.
  Sample Output:
  
    ResourceGroupName : ResourceGroup01
    ServerName : Server01
    StorageAccountName : mystorage
    ScanResultsContainerName : vulnerability-assessment
    RecurringScansInterval : weekly
    EmailSubscriptionAdmins : False
    NotificationEmail : {}`,
  
  rationale: `Vulnerability Assessment (VA) scan reports and alerts will be sent to email ids configured
  at 'Send scan reports to'. This may help in reducing time required for identifying risks and
  taking corrective measures.`,
  
  remediation: `**From Azure Console:**
  
  1. Go to SQL servers
  2. Select a server instance
  3. Click on Security Center
  4. Ensure that Azure Defender for SQL is set to Enabled
  5. Select Configure next to Enabled at subscription-level
  6. In Section Vulnerability Assessment Settings, configure Storage Accounts if not already
  7. Configure email ids for concerned data owners/stakeholders at 'Send scan reports to'
  8. Click Save
  
  **Using Azure PowerShell:**  
  If not already, Enable Advanced Data Security for a SQL Server:
  
    Set-AZSqlServerThreatDetectionPolicy -ResourceGroupName <resource group name>
    -ServerName <server name> -EmailAdmins $True
    
  To enable ADS-VA service and Set 'Send scan reports to'
  
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
        recurringScans {
          emails
        }
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
          path: '[*].recurringScans.emails',
          isEmpty: false,
        }
      },
    ],
  },
}
