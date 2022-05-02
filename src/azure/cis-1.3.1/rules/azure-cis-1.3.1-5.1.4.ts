export default {
  id: 'azure-cis-1.3.1-5.1.4',
  title: 'Azure CIS 5.1.4 Ensure the storage account containing the container with activity logs is encrypted with BYOK (Use Your Own Key)',

  description: 'The storage account with the activity log export container is configured to use BYOK (Use Your Own Key).',

  audit: `**From Azure Console**

  1. Go to Activity log
  2. Select Export
  3. Select Subscription
  4. In section Storage Account, note the name of the Storage account
  5. Close the Export Audit Logs blade. Close the Monitor - Activity Log blade.
  6. In right column, Click service Storage Accounts to access Storage account blade
  7. Click on the storage account name noted in step 4. This will open blade specific to that storage account
  8. In Section SETTINGS click Encryption. It will show Storage service encryption configuration pane.
  9. Ensure Use your own key is checked and Key URI is set.

  **Using Azure Command Line Interface 2.0**

  1. Get storage account id configured with log profile:
      az monitor log-profiles list --query [*].storageAccountId
  2. Ensure the storage account is encrypted with CMK:
      az storage account list --query "[?name=='<Storage Account Name>']"

  In command output ensure keySource is set to Microsoft.Keyvault and keyVaultProperties is not set to null`,

  rationale: 'Configuring the storage account with the activity log export container to use BYOK (Use Your Own Key) provides additional confidentiality controls on log data as a given user must have read permission on the corresponding storage account and must be granted decrypt permission by the CMK.',

  remediation: `**From Azure Console**

  1. In right column, Click service Storage Accounts to access Storage account blade
  2. Click on the storage account name
  3. In Section SETTINGS click Encryption. It will show Storage service encryption configuration pane.
  4. Check Use your own key which will expand Encryption Key Settings
  5. Use option Enter key URI or Select from Key Vault to set up encryption with your own key

  **Using Azure Command Line Interface 2.0**
      az storage account update --name <name of the storage account> --resourcegroup <resource group for a storage account> --encryption-keysource=Microsoft.Keyvault --encryption-key-vault <Key Valut URI> --encryption-key-name <KeyName> --encryption-key-version <Key Version>`,

  references: [
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-data-protection#dp-5-encrypt-sensitive-data-at-rest',
  ],
  severity: 'high',
  gql: `{
    queryazureStorageContainer{
      id
      name
      __typename
      storageAccount{
        encryptionKeySource
      }
    }
  }`,
  resource: 'queryazureStorageContainer[*]',
  conditions: {
    and: [
      {
        path: '@.name',
        equal: 'insights-operational-logs',
      },
      {
        path: '@.storageAccount.encryptionKeySource',
        equal: 'Microsoft.Keyvault'
      },
    ],
  },
}
