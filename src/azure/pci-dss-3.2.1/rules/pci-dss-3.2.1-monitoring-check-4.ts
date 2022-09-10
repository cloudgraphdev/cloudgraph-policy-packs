export default {
  id: 'pci-dss-3.2.1-monitoring-check-4',
  title: 'Monitoring Check 4: Monitor log profile should be created',
  
  description: 'A log profile controls how an activity log is exported. By default, activity logs are retained only for 90 days. Log profiles should be defined so that logs can be exported and stored for a longer duration in order to analyze security activities within an Azure subscription.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**From Azure Console**
  
  Note that log profiles are now a legacy method for sending the activity log to Azure storage or event hubs.
  
  - Navigate to [Monitoring > Activity Log](https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/activityLog).
  - Click Diagnostic settings and select “Looking for the legacy experience? Click here to launch the ‘Export activity log’ blade.”
  - Select the Subscription from the drop-down.
  - Select the desired regions.
  - Select one or both of the following:
    - Export to a storage account. Select a storage account.
    - Export to an event hub. Select a service bus namespace.
  - Set the retention period in days. 0 means logs are kept forever.
  - Click Save.
  
  **Using Command Line:**
  
  - To create a log profile, use the az monitor log-profiles create command with the desired flags (see the Azure documentation for details):
  
          az monitor log-profiles create --categories create
                                      --days
                                      --enabled true
                                      --location
                                      --locations
                                      --name
                                      [--service-bus-rule-id]
                                      [--storage-account-id]
                                      [--subscription]
                                      [--tags`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/platform-logs-overview',
      'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log#legacy-collection-methods',
      'https://docs.microsoft.com/en-us/cli/azure/monitor/log-profiles?view=azure-cli-latest#az-monitor-log-profiles-create',
  ],
  gql: `{
    queryazureLogProfile {
      id
      __typename
      retentionPolicy {
        enabled
        days
      }
    }
  }`,
  resource: 'queryazureLogProfile[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.retentionPolicy.enabled',
        equal: true,
      },
      {
        path: '@.retentionPolicy.days',
        equal: 0,
      },
    ], 
  },
}
