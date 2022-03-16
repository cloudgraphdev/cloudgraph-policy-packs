export default {
  id: 'azure-cis-1.3.1-5.3',  
  title: 'Azure CIS 5.3 Ensure that Diagnostic Logs are enabled for all services which support it (Manual)',
  
  description: `Diagnostic Logs capture activity to the data access plane while the Activity log is a
  subscription-level log for the control plane. Resource-level diagnostic logs provide insight
  into operations that were performed within that resource itself, for example, getting a
  secret from a Key Vault. Currently, 32 Azure resources support Diagnostic Logging (See the
  references section for a complete list), including Network Security Groups, Load Balancers,
  Key Vault, AD, Logic Apps and CosmosDB. The content of these logs varies by resource type.
  For example, Windows event system logs are a category of diagnostics logs for VMs, and
  blob, table, and queue logs are categories of diagnostics logs for storage accounts.
  A number of back-end services were not configured to log and store Diagnostic Logs for
  certain activities or for a sufficient length. It is crucial that logging systems are correctly
  configured to log all relevant activities and retain those logs for a sufficient length of time.
  By default, Diagnostic Logs are not enabled. Given that the mean time to detection in an
  enterprise is 240 days, a minimum retention period of two years is recommended.
  Note: The CIS Benchmark covers some specific Diagnostic Logs separately.
  
    3.3 Ensure Storage logging is enabled for Queue service for read, write, and delete requests
    6.4 Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'`,
  
  audit: `**From Azure Console:**
  
  The specific steps for configuring resources within the Azure
  console vary depending on resource, but typically the steps are:

  1. Go to the resource
  2. Click on Diagnostic settings
  3. In the blade that appears, click "Add diagnostic setting"
  4. Configure the diagnostic settings
  5. Click on Save
  
  **Using Azure Command Line Interface**  
  Use the following command to list the resource manager resources.

    az resource list | jq '.[].id' | sed 's/\"//g' > resources.txt

  Check if diagnostic logging was present.

    for resource in \`cat resources.txt\`; do
      echo $resource && az monitor diagnostic-settings list --resource
    $resource 2>/dev/null| jq '.value'
    done

  The output from above will give the resource id followed
  by [] if a diagnostic log is available but not present.`,
  
  rationale: `A lack of Diagnostic Logs reduces the visibility into the data plane and therefore an
  organization's ability to detect reconnaissance, authorization attempts or other malicious
  activity. Unlike Activity Logs, Diagnostic Logs are not enabled by default. Specifically,
  without Diagnostic Logs it would be impossible to tell which entities had accessed a data
  store that which was breached. In addition, alerts for failed attempts to access APIs for Web
  Services or Databases are only possible when Diagnostic Logging is enabled.`,
  
  remediation: `Azure Subscriptions should log every access and operation for all resources.
  Logs should be sent to Storage and a Log Analytics Workspace or equivalent third-party
  system.
  Logs should be kept in readily accessible storage for a minimum of one year, and then
  moved to inexpensive cold storage for a duration of time as necessary. If retention policies
  are set but storing logs in a Storage Account is disabled (for example, if only Event Hubs or
  Log Analytics options are selected), the retention policies have no effect.
  Enable all logging at first, and then be more aggressive moving data to cold storage if the
  volume of data becomes a cost concern.
  
  **From Azure Console:**
  The specific steps for configuring resources within the Azure console vary depending on resource, but typically the steps are:

  1. Go to the resource
  2. Click on Diagnostic settings
  3. In the blade that appears, click "Add diagnostic setting"
  4. Configure the diagnostic settings
  5. Click on Save
  
  **Using Azure Command Line Interface**  
  Enable logging for all resources which support Diagnostic Logs to ensure interactions
  within the resource are logged and available. The skeleton command for creating
  logs and metrics with unlimited retention on a
  generic resource are shown below.
  
    az monitor diagnostic-settings create --resource {ID} -n {name}
      --event-hub-rule {eventHubRuleID} 
      --storage-account {storageAccount}
      --logs '[{
      "category": "WorkflowRuntime",
      "enabled": true,
      "retentionPolicy": {
        "enabled": false,
        "days": 0
      }
      }]'
      --metrics '[{
      "category": "WorkflowRuntime",
      "enabled": true,
      "retentionPolicy": {
        "enabled": false,
        "days": 0
      }
      }]'`,
  
  references: [
    'https://docs.microsoft.com/en-us/azure/security/fundamentals/log-audit',
    'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/collect-activity-logs',
    'https://docs.microsoft.com/en-us/azure/key-vault/key-vault-logging',
    'https://docs.microsoft.com/en-us/cli/azure/monitor/diagnostic-settings?view=azure-cli-latest',
    'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-logs-overview',
    'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-logs-schema',
    'https://docs.microsoft.com/en-us/azure/cdn/cdn-azure-diagnostic-logs',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-4-enable-logging-for-azure-resources',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-5-centralize-security-log-management-and-analysis', 
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-5-centralize-security-log-management-and-analysis',
  ],  
  severity: 'medium',
}