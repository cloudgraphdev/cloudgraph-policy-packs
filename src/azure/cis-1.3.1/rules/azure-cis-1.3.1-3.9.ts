export default {
  id: 'azure-cis-1.3.1-3.9',  
  title: 'Azure CIS 3.9 Ensure storage for critical data are encrypted with Customer Managed Key',
  
  description: 'Enable sensitive data encryption at rest using Customer Managed Keys rather than Microsoft Managed keys',
  
  audit: `**From Azure Console:**
  
  1. Go to Storage Accounts
  2. For each storage account, go to Encryption
  3. Ensure that Encryption type is set to Customer Managed Keys`,
  
  rationale: 'By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.',
  
  remediation: `**From Azure Console:**
  
  1. Go to Storage Accounts
  2. For each storage account, go to Encryption
  3. Set Customer Managed Keys
  4. Select the Encryption key and enter the appropriate setting value
  5. Click Save`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption',
      'https://docs.microsoft.com/en-us/azure/security/fundamentals/data-encryption-best-practices#protect-data-at-rest',
      'https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption#azure-storage-encryption-versus-disk-encryption',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-data-protection#dp-1-discovery,-classify-and-label-sensitive-data',
  ],
  gql: `{
    queryazureStorageAccount {
      id
      __typename
      encryptionKeySource
    }
  }`,
  resource: 'queryazureStorageAccount[*]',
  severity: 'medium',
  conditions: {
    path: '@.encryptionKeySource',
    notEqual: 'Microsoft.Storage',
  },
}
