export default {
  id: 'azure-cis-1.3.1-3.5',  
  title: 'Azure CIS 3.5 Ensure that \'Public access level\' is set to Private for blob containers',
  
  description: 'Disable anonymous access to blob containers and disallow blob public access on storage account.',
  
  audit: `**From Azure Console**
  
  1. Go to Storage Accounts
  2. For each storage account, go to Containers under BLOB SERVICE
  3. For each container, click Access policy
  4. Ensure that Public access level is set to Private (no anonymous access)
  5. For each storage account, go to Allow Blob public access in Configuration
  6. Ensure Disabled if no anonymous access is needed on the storage account
  
  **Using Azure Command Line Interface 2.0**  
  Ensure the below command output contains null
  
      az storage container list --account-name <accountName> --account-key <accountKey> --query '[*].properties.publicAccess'
  
  Ensure allowBlobPublicAccess is false
  
      az storage account show --name <storage-account> --resource-group <resource-group> --query allowBlobPublicAccess --output tsv`,
  
  rationale: 'Anonymous, public read access to a container and its blobs can be enabled in Azure Blob storage. It grants read-only access to these resources without sharing the account key, and without requiring a shared access signature. It is recommended not to provide anonymous access to blob containers until, and unless, it is strongly desired. A shared access signature token should be used for providing controlled and timed access to blob containers. If no anonymous access is needed on the storage account, it’s recommended to set allowBlobPublicAccess false.',
  
  remediation: `**From Azure Console**  
  First, follow Microsoft documentation and created shared access signature tokens for your blob containers. Then,
  
  1. Go to Storage Accounts
  2. For each storage account, go to Containers under BLOB SERVICE
  3. For each container, click Access policy
  4. Set Public access level to Private (no anonymous access)
  5. For each storage account, go to Allow Blob public access in Configuration
  6. Set Disabled if no anonymous access is needed on the storage account
  
  **Using Azure Command Line Interface 2.0**
  
  1. Identify the container name from the audit command
  2. Set the permission for public access to private(off) for the above container name, using the below command
  
          az storage container set-permission --name <containerName> --public-access off --account-name <accountName> --account-key <accountKey>
  
  3. Set Disabled if no anonymous access is wanted on the storage account
  
          az storage account update --name <storage-account> --resource-group <resource-group> --allow-blob-public-access false`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/storage/blobs/storage-manage-access-to-resources',
      'https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-2-define-enterprise-segmentation-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-network-security#ns-1-implement-security-for-internal-traffic',
  ],
  gql: `{
    queryazureStorageAccount {
    id
    __typename
    allowBlobPublicAccess
  }
  }`,
  resource: 'queryazureStorageAccount[*]',
  severity: 'high',
  conditions: {
    path: '@.allowBlobPublicAccess',
    equal: 'No',
  },
}
