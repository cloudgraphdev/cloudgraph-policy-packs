export default {
  id: 'azure-cis-1.3.1-5.1.5',
  title: "Azure CIS 5.1.5 Ensure that logging for Azure KeyVault is 'Enabled'",

  description:
    'Enable AuditEvent logging for key vault instances to ensure interactions with key vaults are logged and available.',

  audit: `**From Azure Console**

  1. Go to Key vaults
  2. For each Key vault
  3. Go to Diagnostic Logs
  4. Click on Edit Settings
  5. Ensure that Archive to a storage account is Enabled
  6. Ensure that AuditEvent is checked and the retention days is set to 180 days or as appropriate

  **Using Azure Command Line Interface 2.0**

  List all key vaults
      az keyvault list

  For each keyvault id
      az monitor diagnostic-settings list --resource <id>

  Ensure that storageAccountId is set as appropriate. Also, ensure that category and days are set. One of the sample outputs is as below.

  "logs": [
    {
      "category": "AuditEvent",
      "enabled": true,
      "retentionPolicy": {
        "days": 180,
        "enabled": true
      }
    }
  ]`,

  rationale:
    'Monitoring how and when key vaults are accessed, and by whom enables an audit trail of interactions with confidential information, keys and certificates managed by Azure Keyvault. Enabling logging for Key Vault saves information in an Azure storage account that the user provides. This creates a new container named insights-logs-auditevent automatically for the specified storage account, and this same storage account can be used for collecting logs for multiple key vaults.',

  remediation:
    'Follow Microsoft Azure documentation and setup Azure Key Vault Logging.',

  references: [
    'https://docs.microsoft.com/en-us/azure/key-vault/key-vault-logging',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-4-enable-logging-for-azure-resources',
  ],
  severity: 'medium',
}
