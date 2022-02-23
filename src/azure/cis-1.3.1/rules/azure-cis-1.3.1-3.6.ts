export default {
  id: 'azure-cis-1.3.1-3.6',  
  title: 'Azure CIS 3.6 Ensure default network access rule for Storage Accounts is set to deny',
  
  description: 'Restricting default network access helps to provide a new layer of security, since storage accounts accept connections from clients on any network. To limit access to selected networks, the default action must be changed.',
  
  audit: `**From Azure Console**
  
  1. Go to Storage Accounts
  2. For each storage account, Click on the settings menu called Firewalls and virtual networks.
  3. Ensure that Allow access from All networks is not selected.
  
  **Using Azure Command Line Interface 2.0**  
  Ensure defaultAction is not set to Allow.
  
      az storage account list --query '[*].networkRuleSet'`,
  
  rationale: 'Storage accounts should be configured to deny access to traffic from all networks (including internet traffic). Access can be granted to traffic from specific Azure Virtual networks, allowing a secure network boundary for specific applications to be built. Access can also be granted to public internet IP address ranges, to enable connections from specific internet or on-premises clients. When network rules are configured, only applications from allowed networks can access a storage account. When calling from an allowed network, applications continue to require proper authorization (a valid access key or SAS token) to access the storage account.',
  
  remediation: `**From Azure Console**
  
  1. Go to Storage Accounts
  2. For each storage account, Click on the settings menu called Firewalls and virtual networks.
  3. Ensure that you have elected to allow access from Selected networks.
  4. Add rules to allow traffic from specific network.
  5. Click Save to apply your changes.
  
  **Using Azure Command Line Interface 2.0**  
  Use the below command to update default-action to Deny.
  
      az storage account update --name <StorageAccountName> --resource-group <resourceGroupName> --default-action Deny`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-2-define-enterprise-segmentation-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-network-security#ns-1-implement-security-for-internal-traffic',
  ],
  gql: `{
    queryazureStorageAccount {
    id
    __typename
    networkRuleSetDefaultAction
  }
  }`,
  resource: 'queryazureStorageAccount[*]',
  severity: 'medium',
  conditions: {
    path: '@.networkRuleSetDefaultAction',
    notEqual: 'Allow',
  },
}
