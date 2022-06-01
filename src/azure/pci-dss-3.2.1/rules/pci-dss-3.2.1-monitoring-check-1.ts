export default {
  id: 'azure-pci-dss-3.2.1-monitoring-check-1',  
  title: 'Monitoring Check 1: Monitor audit profile should log all activities',

  description: 'The log profile should be configured to export all activities from the control/management plane. A log profile controls how the activity log is exported. Configuring the log profile to collect logs for the categories “write”, “delete” and “action” ensures that all the control/management plane activities performed on the subscription are exported.',

  audit: '',

  rationale: '',

  remediation: `**Azure Portal**
  
  When you create a log profile using the Azure Portal, the write, delete, and action categories are selected by default. However, if you created the log profile via the command line, remediation is not possible via the portal.
  
  **Azure CLI**
  
  To log all activities, follow the Azure documentation to create a log profile and set the desired flags, including --categories "Delete" "Write" "Action":
  
      az monitor log-profiles create --categories
                                  --days
                                  --enabled {false, true}
                                  --location
                                  --locations
                                  --name
                                  [--service-bus-rule-id]
                                  [--storage-account-id]
                                  [--subscription]
                                  [--tags]`,

  references: [
      'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log#configure-log-profile-using-azure-cli',
      'https://docs.microsoft.com/en-us/cli/azure/monitor/log-profiles?view=azure-cli-latest',
  ],
  gql: `{
    queryazureLogProfile {
      id
      __typename
      categories
    }
  }`,
  resource: 'queryazureLogProfile[*]',
  severity: 'high',
  conditions: {
    and: [
      {
        path: '@.categories',
        contains: 'Action',
      },
      {
        path: '@.categories',
        contains: 'Write',
      },
      {
        path: '@.categories',
        contains: 'Delete',
      },
    ], 
  }, 
}