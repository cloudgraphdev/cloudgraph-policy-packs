// similar to CIS 3.1
export default {
  id: 'azure-nist-800-53-rev4-6.4',
  title: "Azure NIST 6.4 Ensure that 'Secure transfer required' is set to 'Enabled'",

  description: 'Enable data encryption in transit.',

  audit: `**From Azure Console**

  1. Go to Storage Accounts
  2. For each storage account, go to Configuration
  3. Ensure that Secure transfer required is set to Enabled

  **Using Azure Command Line Interface 2.0**  
  Use the below command to ensure the Secure transfer required is enabled for all the Storage Accounts by ensuring the output contains true for each of the Storage Accounts.

          z storage account list --query [*].[name,enableHttpsTrafficOnly]`,

  rationale:
    "The secure transfer option enhances the security of a storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access storage accounts, the connection must use HTTPS. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn’t support HTTPS for custom domain names, this option is not applied when using a custom domain name.",

  remediation: `**From Azure Console**

  1. Go to Storage Accounts
  2. For each storage account, go to Configuration
  3. Set Secure transfer required to Enabled

  **Using Azure Command Line Interface 2.0**  
  Use the below command to enable Secure transfer required for a Storage Account

          az storage account update --name <storageAccountName> --resource-group <resourceGroupName> --https-only true`,

  references: [
    'https://docs.microsoft.com/en-us/azure/storage/blobs/security-recommendations#encryption-in-transit',
    'https://docs.microsoft.com/en-us/cli/azure/storage/account?view=azure-cli-latest#az_storage_account_list',
    'https://docs.microsoft.com/en-us/cli/azure/storage/account?view=azure-cli-latest#az_storage_account_update',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-data-protection#dp-4-encrypt-sensitive-information-in-transit',
  ],  
  gql: `{
    queryazureStorageAccount {
      id
      __typename
      enableHttpsTrafficOnly
    }
  }`,
  resource: 'queryazureStorageAccount[*]',
  severity: 'medium',
  conditions: {
    path: '@.enableHttpsTrafficOnly',
    equal: 'Yes',
  },
}