export default {
  id: 'azure-pci-dss-3.2.1-monitoring-check-2',  
  title: 'Monitoring Check 2: Monitor Activity Log Alert should exist for Update Security Policy',
  
  description: 'Create an activity log alert for the Update Security Policy event. Monitoring for Update Security Policy events gives insight into changes to security policy and may reduce the time it takes to detect suspicious activity.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**Azure Portal**
  
  - Navigate to Monitor > Alerts.
  - Select New alert rule.
  - Under Scope, click Select Resource.
  - Select your subscription and click Done.
  - Under Condition, click Select Condition.
  - In the search, enter the term “Update security policy” and select “Update security policy (Microsoft.Security/policies).”
  - Select Done.
  - Under Action group, click Select action group.
  - Select the desired action group to attach to the alert rule, or create one if needed, and click Select.
  - Enter an alert rule name and description.
  - Select a resource group.
  - Click Create alert rule.
  
  **Azure CLI**
  
  Create a Monitor Activity Log Alert for Update Security Policy, replacing _<resource_group_name>_, _<subscription_id>_, and _<action_group>_ with your own values:
  
      az monitor activity-log alert create --name updateSecurityPolicy \
      --resource-group <resource_group_name> \
      --condition category="Security" and \
      operationName="Microsoft.Security/policies/write" \
      --scope "/subscriptions/<subscription_id>" \
      --action-group <action_group>`,
  
  references: [
      'https://docs.microsoft.com/en-in/azure/azure-monitor/platform/alerts-activity-log',
      'https://docs.microsoft.com/en-us/cli/azure/monitor/activity-log/alert?view=azure-cli-latest#az-monitor-activity-log-alert-create',
  ],
  gql: `{
    queryazureResourceGroup {
      id
      __typename
      activityLogAlerts {
        region
        enabled
        condition {
          allOf {
            field
            equals
          }
        }
      }
    }
  }`,
  resource: 'queryazureResourceGroup[*]',
  severity: 'medium',
  conditions: {
    path: '@.activityLogAlerts',
    array_any: {
      and: [
        {
          path: '[*].region',
          equal: 'global',
        },
        {
          path: '[*].enabled',
          equal: true,
        },
        {
          path: '[*].condition.allOf',
          array_any: {
            and: [
              {
                path: '[*].field',
                equal: 'operationName',
              },
              {
                path: '[*].equals',
                equal: 'Microsoft.Security/policies/write',
              },
            ]
          },
        },
      ],
    },
  },
}