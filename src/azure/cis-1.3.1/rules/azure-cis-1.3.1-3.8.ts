export default {
  id: 'azure-cis-1.3.1-3.8',
  title: 'Azure CIS 3.8 Ensure soft delete is enabled for Azure Storage',

  description: `The Azure Storage blobs contain data like ePHI, Financial, secret or personal. Erroneously modified or deleted accidentally by an application or other storage account user cause data loss or data unavailability.

  It is recommended the Azure Storage be made recoverable by enabling **soft delete** configuration. This is to save and recover data when blobs or blob snapshots are deleted.`,

  audit: `**From Azure Console:**

  1. Go to Storage Account
  2. For each Storage Account, navigate to Data protection
  3. Ensure that soft delete is enabled

  **Using Azure Command-Line Interface 2.0:**
  Ensure that the output of the below command contains enabled status as true and days is not empty or null

      az storage blob service-properties delete-policy show --account-name <StorageAccountName>`,

  rationale: `There could be scenarios where users accidentally run delete commands on Azure Storage blobs or blob snapshot or attacker/malicious user does it deliberately to cause disruption. Deleting an Azure Storage blob leads to immediate data loss / non-accessible data.

  There is a property of Azure Storage blob service to make recoverable blobs.

  - **Soft Delete**

      Enabling this configuration for azure storage ensures that even if blobs/data were deleted from the storage account, Blobs/data objects remain recoverable for a particular time which set in the "Retention policies" [Retention policies can be 7 days to 365 days].`,

  remediation: `**From Azure Console:**

  1. Go to Storage Account
  2. For each Storage Account, navigate to Data Protection
  3. Select set soft delete enabled and enter a number of days you want to retain soft deleted data.

  **Using Azure Command-Line Interface 2.0:**
  Update retention days in below command

      az storage blob service-properties delete-policy update --days-retained <RetentionDaysValue> --account-name <StorageAccountName> --enable true`,

  references: [
    'https://docs.microsoft.com/en-us/azure/storage/blobs/storage-blob-soft-delete',
  ],
  gql: `{
    queryazureStorageAccount {
      id
      __typename
      blobServiceProperties {
        deleteRetentionPolicyEnabled
        deleteRetentionPolicyDays
      }
    }
  }`,
  resource: 'queryazureStorageAccount[*]',
  severity: 'high',
  conditions: {
    and: [
      {
        path: '@blobServiceProperties.deleteRetentionPolicyEnabled',
        equal: true,
      },
      {
        path: '@blobServiceProperties.deleteRetentionPolicyDays',
        isEmpty: false,
      },
    ],
  },
}
