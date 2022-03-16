export default {
  id: 'azure-cis-1.3.1-5.1.2',
  title:
    'Azure CIS 5.1.2 Ensure Diagnostic Setting captures appropriate categories',

  description:
    'The diagnostic setting should be configured to log the appropriate activities from the control/management plane.',

  audit: `**From Azure Console:**

  1. Go to Azure Monitor
  2. Click Activity log
  3. Click on Diagnostic settings
  4. Click on Edit Settings for the diagnostic settings entry
  5. Ensure that the following categories are checked: Administrative, Alert, Policy, and Security

  **Using Azure Command Line Interface 2.0**
  Ensure the categories set to: Administrative, Alert, Policy, and Security
      az monitor diagnostic-settings subscription list

  **AZ PowerShell cmdlets**
  Ensure the categories Administrative, Alert, Policy, and Security are set to Enabled:True
      get-AzDiagnosticSetting -ResourceId subscriptions/<subscriptionID>`,

  rationale:
    'A diagnostic setting controls how the diagnostic log is exported. Capturing the diagnostic setting categories for appropriate control/management plane activities allows proper alerting.',

  remediation: `**From Azure Console:**

  1. Go to Azure Monitor
  2. Click Activity log
  3. Click on Diagnostic settings
  4. Click on Edit Settings for the diagnostic settings entry
  5. Ensure that the following categories are checked: Administrative, Alert, Policy, and Security`,

  references: [
    'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings',
    'https://docs.microsoft.com/en-us/azure/azure-monitor/samples/resource-manager-diagnostic-settings',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-4-enable-logging-for-azure-resources',
  ],
  severity: 'medium',
  gql: `{
    queryazureDiagnosticSetting{
      id
      __typename
      appropiateCategories
      storageAccount{
        storageContainers{
          name
        }
      }
    }
  }`,
  resource: 'queryazureDiagnosticSetting[*]',
  conditions: {
    and: [
      {
        path: '[*].appropiateCategories',
        equal: true,
      },
      {
        path: '@.storageAccount',
        array_any: {
          path: '[*].storageContainers',
          array_any: {
            path: '[*].name',
            equal: 'insights-activity-logs',
          },
        },
      },
    ],
  },
}
