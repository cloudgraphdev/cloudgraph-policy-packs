export default {
  id: 'azure-cis-1.3.1-5.1.1',
  title: 'Azure CIS 5.1.1 Ensure that a \'Diagnostics Setting\' exists',

  description: 'Enable Diagnostic settings for exporting activity logs. Diagnostic setting are available for each individual resources within a subscription. Settings should be configured for all appropriate resources for your environment.',

  audit: `**From Azure Console:**

  1. Go to Diagnostics settings
  2. Ensure that a Diagnostic status is enabled on all appropriate resources.`,

  rationale: 'A diagnostic setting controls how a diagnostic log is exported. By default, logs are retained only for 90 days. Diagnostic settings should be defined so that logs can be exported and stored for a longer duration in order to analyze security activities within an Azure subscription.',

  remediation: `**From Azure Console:**

  1. Click on the resource that has a diagnostic status of disabled
  2. Select Add Diagnostic Settings
  3. Enter a Diagnostic setting name
  4. Select the appropriate log, metric, and destination. (This may be Log Analytics/Storage account or Event Hub)
  5. Click save.

  Repeat these step for all resources as needed.`,

  references: [
      'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings',
      'https://docs.microsoft.com/en-us/azure/azure-monitor/samples/resource-manager-diagnostic-settings',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-4-enable-logging-for-azure-resources',
  ],
  severity: 'medium'
}
