export default {
  id: 'azure-cis-1.3.1-4.2.5',  
  title: 'Azure CIS 4.2.5 Ensure that VA setting \'Also send email notifications to admins and subscription owners\' is set for a SQL server',
  
  description: `Enable Vulnerability Assessment (VA) setting 'Also send email notifications to admins and subscription owners'.`,
  
  audit: `**From Azure Console:**
  
  1. Go to SQL servers
  2. Select a server instance
  3. Click on Security Center
  4. Ensure that Azure Defender for SQL is set to Enabled
  5. Select Configure next to Enabled at subscription-level
  6. In Section Vulnerability Assessment Settings, Ensure Storage Accounts is configured.
  7. In Section Vulnerability Assessment Settings, Ensure Also send email notifications to admins and subscription owners is checked/enabled.
  
  **Using Azure PowerShell:**  
  Get the list of all SQL Servers
  
    Get-AzSqlServer
    
  For each Server
  
    Get-AzSqlServerVulnerabilityAssessmentSetting -ResourceGroupName <resource
    group name> -ServerName <server name>
    
  Ensure that value for parameter EmailSubscriptionAdmin is set to true.
  Sample Output:
  
    ResourceGroupName : ResourceGroup01
    ServerName : Server01
    StorageAccountName : mystorage
    ScanResultsContainerName : vulnerability-assessment
    RecurringScansInterval : weekly
    EmailSubscriptionAdmins : False
    NotificationEmail : {}`,
  
  rationale: `VA scan reports and alerts will be sent to admins and subscription owners by enabling
  setting 'Also send email notifications to admins and subscription owners'. This may help in
  reducing time required for identifying risks and taking corrective measures.`,
  
  remediation: `**From Azure Console:**
  
  1. Go to SQL servers
  2. Select a server instance
  3. Click on Security Center
  4. Select Configure next to Enabled at subscription-level
  5. In Section Vulnerability Assessment Settings, configure Storage Accounts if not already
  6. Check/enable 'Also send email notifications to admins and subscription owners'
  7. Click Save
  
  **Using Azure PowerShell:**  
  If not already, Enable Advanced Data Security for a SQL Server:
  
    Set-AZSqlServerThreatDetectionPolicy -ResourceGroupName <resource group name>
    -ServerName <server name> -EmailAdmins $True
    
  To enable ADS-VA service and Set 'Also send email notifications to admins and subscription owners'
  
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
          emailSubscriptionAdmins
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
          path: '[*].recurringScans.emailSubscriptionAdmins',
          equal: true,
        },
      },
    ],
  },
}
