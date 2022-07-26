export default {
  id: 'azure-nist-800-53-rev4-2.4',  
  title: 'Azure NIST 2.4 Monitor log profile should have activity logs for global services and all regions',
  
  description: 'Configure the log profile to export activities from all Azure supported regions/locations including global. This rule is evaluated against all resource locations that Fugue has permission to scan.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**From Azure Console**
  
  - Note this rule applies to the legacy experience for Azure Activity log.
  - Navigate to [Activity log](https://portal.azure.com/#blade/Microsoft_Azure_ActivityLog/ActivityLogBlade).
  - Select Diagnostics setting.
  - Click Looking for the legacy experience? Click here to launch the ‘Export activity log’ blade.
  - From the Regions drop-down, check Select all.
  - Click Save.
  
   **Using Command Line:**
  
  - To enable activity logs for global services and all regions:
  
          az monitor log-profiles update --name default`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings',
      'https://docs.microsoft.com/en-us/cli/azure/monitor/log-profiles?view=azure-cli-latest#az-monitor-log-profiles-update',
  ],
  gql: `{
    queryazureLogProfile {
      id
      __typename
      name
      locations
    }
  }`,
  resource: 'queryazureLogProfile[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.name',
        equal: 'default',
      },
      {
        and: [
          {
            path: '@.locations',
            contains: 'centralus',
          },
          {
            path: '@.locations',
            contains: 'eastus',
          },
          {
            path: '@.locations',
            contains: 'northcentralus',
          },
          {
            path: '@.locations',
            contains: 'southcentralus',
          },
          {
            path: '@.locations',
            contains: 'westus',
          },
          {
            path: '@.locations',
            contains: 'francecentral',
          },
          {
            path: '@.locations',
            contains: 'germanynorth',
          },
          {
            path: '@.locations',
            contains: 'swedencentral',
          },
          {
            path: '@.locations',
            contains: 'global',
          },
        ],
      },
    ],
  },
}
