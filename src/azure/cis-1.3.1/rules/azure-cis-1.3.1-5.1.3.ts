export default {
  id: 'azure-cis-1.3.1-5.1.3',
  title:
    'Azure CIS 5.1.3 Ensure the storage container storing the activity logs is not publicly accessible',

  description:
    'The storage account container containing the activity log export should not be publicly accessible.',

  audit: `**From Azure Console**

  1. Go to Activity log
  2. Select Export
  3. Select Subscription
  4. In section Storage Account, note the name of the Storage account
  5. Close the Export Audit Logs blade. Close the Monitor - Activity Log blade.
  6. In right column, Click service Storage Accounts to access Storage account blade
  7. Click on the storage account name noted in step 4. This will open blade specific to that storage account
  8. In Section Blob Service click Containers. It will list all the containers in next blade
  9. Look for a record with container named as insight-operational-logs. Click ... from right most column to open Context menu
  10. Click Access Policy from Context Menu and ensure Public Access Level is set to Private (no anonymous access)

  **Using Azure Command Line Interface 2.0**

  1. Get storage account id configured with log profile:
      az monitor log-profiles list --query [*].storageAccountId

  2. Ensure the container storing activity logs (insights-operational-logs) is not publicly accessible:
      az storage container list --account-name <Storage Account Name> --query "[?name=='insights-operational-logs']"

  In command output ensure publicAccess is set to null`,

  rationale:
    "Allowing public access to activity log content may aid an adversary in identifying weaknesses in the affected account's use or configuration.",

  remediation: `**From Azure Console**

  1. Search for Storage Accounts to access Storage account blade
  2. Click on the storage account name
  3. In Section Blob Service click Containers. It will list all the containers in next blade
  4. Look for a record with container named as insight-operational-logs. Click ... from right most column to open Context menu
  5. Click Access Policy from Context Menu and set Public Access Level to Private (no anonymous access)

  **Using Azure Command Line Interface 2.0**
      az storage container set-permission --name insights-operational-logs --account-name <Storage Account Name> --public-access off`,

  references: [
    'https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-network-security#ns-1-implement-security-for-internal-traffic',
  ],
  severity: 'high',
  gql: `{
    queryazureStorageContainer{
      id
      name
      __typename
      name
      publicAccess
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
        path: '@.publicAccess',
        equal: 'None',
      },
    ],
  },
}
