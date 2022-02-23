export default {
  id: 'azure-cis-1.3.1-3.2',  
  title: 'Azure CIS 3.2 Ensure that storage account access keys are periodically regenerated (Manual)',
  
  description: 'Regenerate storage account access keys periodically.',
  
  audit: `**From Azure Console**
  
  1. Go to Storage Accounts
  2. For each storage account, go to Activity log
  3. Under Timespan drop-down, select Custom and choose Start time and End time such that it ranges 90 days
  4. Enter RegenerateKey in the Search text box
  5. Click Apply
  
  It should list out all RegenerateKey events. If no such event exists, then this is a finding.
  
  **Using Azure Command Line Interface 2.0**
  
  1. Get a list of storage accounts
  
          az storage account list
  
  Make a note of id, name and resourceGroup.
  
  2. For every storage account make sure that key is regenerated in past 90 days.
  
          az monitor activity-log list --namespace Microsoft.Storage --offset 90d --query "[?contains(authorization.action, 'regenerateKey')]" --resource-id <resource id>
  
  The output should contain
  
      "authorization"/"scope": <your_storage_account> AND "authorization"/"action": "Microsoft.Storage/storageAccounts/regenerateKey/action" AND "status"/"localizedValue": "Succeeded" "status"/"Value": "Succeeded"`,
  
  rationale: 'When a storage account is created, Azure generates two 512-bit storage access keys, which are used for authentication when the storage account is accessed. Rotating these keys periodically ensures that any inadvertent access or exposure does not result in these keys being compromised.',
  
  remediation: 'Follow Microsoft Azure documentation for regenerating storage account access keys.',
  
  references: [
      'https://docs.microsoft.com/en-us/azure/storage/common/storage-create-storage-account#regenerate-storage-access-keys',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-1-protect-and-limit-highly-privileged-users',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-2-restrict-administrative-access-to-business-critical-systems',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-identity-management#im-2-manage-application-identities-securely-and-automatically',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
  ],
  severity: 'high',
}
