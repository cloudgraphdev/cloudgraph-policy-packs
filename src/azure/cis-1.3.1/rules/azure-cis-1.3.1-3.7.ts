export default {
  id: 'azure-cis-1.3.1-3.7',  
  title: 'Azure CIS 3.7 Ensure \'Trusted Microsoft Services\' is enabled for Storage Account access (Manual)',
  
  description: 'Some Microsoft services that interact with storage accounts operate from networks that can\'t be granted access through network rules. To help this type of service work as intended, allow the set of trusted Microsoft services to bypass the network rules. These services will then use strong authentication to access the storage account. If the Allow trusted Microsoft services exception is enabled, the following services: Azure Backup, Azure Site Recovery, Azure DevTest Labs, Azure Event Grid, Azure Event Hubs, Azure Networking, Azure Monitor and Azure SQL Data Warehouse (when registered in the subscription), are granted access to the storage account.',
  
  audit: `**From Azure Console**
  
  1. Go to Storage Accounts
  2. For each storage account, Click on the settings menu called Firewalls and virtual networks.
  3. Click on Selected networks.
  4. Ensure that Allow trusted Microsoft services to access this storage account is checked in Exceptions.
  
          Using Azure Command Line Interface 2.0 Ensure bypass contains AzureServices az storage account list --query '[*].networkRuleSet'`,
  
  rationale: 'Turning on firewall rules for storage account will block access to incoming requests for data, including from other Azure services. This includes using the Portal, writing logs, etc. We can re-enable functionality. The customer can get access to services like Monitor, Networking, Hubs, and Event Grid by enabling "Trusted Microsoft Services" through exceptions. Also, Backup and Restore of Virtual Machines using unmanaged disks in storage accounts with network rules applied is supported via creating an exception.',
  
  remediation: `**From Azure Console**
  
  1. Go to Storage Accounts
  2. For each storage account, Click on the settings menu called Firewalls and virtual networks.
  3. Ensure that you have elected to allow access from 'Selected networks'.
  4. Enable check box for Allow trusted Microsoft services to access this storage account.
  5. Click Save to apply your changes.
  
  **Using Azure Command Line Interface 2.0**  
  Use the below command to update trusted Microsoft services.
  
      az storage account update --name <StorageAccountName> --resource-group <resourceGroupName> --bypass AzureServices`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-network-security#ns-1-implement-security-for-internal-traffic',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-2-define-enterprise-segmentation-strategy',
  ],  
  severity: 'high',
}
