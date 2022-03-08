export default {
  id: 'azure-cis-1.3.1-6.4',  
  title: 'Azure CIS 6.4 Ensure that Network Security Group Flow Log retention period is \'greater than 90 days\'',
  
  description: 'Network Security Group Flow Logs should be enabled and the retention period is set to greater than or equal to 90 days.',
  
  audit: `**From Azure Console**
  
  1. Go to Network Watcher
  2. Select NSG flow logs blade in the Logs section
  3. Select each Network Security Group from the list
  4. Ensure Status is set to On
  5. Ensure Retention (days) setting greater than 90 days
  
  **Using Azure Command Line Interface 2.0**
  
      az network watcher flow-log show --resource-group <resourceGroup> --nsg <NameorID of the NetworkSecurityGroup> --query 'retentionPolicy'
  
  Ensure that enabled is set to true and days is set to greater then or equal to 90.`,
  
  rationale: 'Flow logs enable capturing information about IP traffic flowing in and out of network security groups. Logs can be used to check for anomalies and give insight into suspected breaches.',
  
  remediation: `**From Azure Console**
  
  1. Go to Network Watcher
  2. Select NSG flow logs blade in the Logs section
  3. Select each Network Security Group from the list
  4. Ensure Status is set to On
  5. Ensure Retention (days) setting greater than 90 days
  6. Select your storage account in the Storage account field
  7. Select Save
  
  **Using Azure Command Line Interface 2.0**  
  Enable the NSG flow logs and set the Retention (days) to greater than or equal to 90 days.
  
      az network watcher flow-log configure --nsg <NameorID of the Network Security Group> --enabled true --resource-group <resourceGroupName> --retention 91 --storage-account <NameorID of the storage account to save flow logs>`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-overview',
      'https://docs.microsoft.com/en-us/cli/azure/network/watcher/flow-log?view=azure-cli-latest',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-6-configure-log-storage-retention',
  ],    
  gql: `{
    queryazureNetworkSecurityGroup {
      id
      __typename
      flowLogs {
        retentionPolicyEnabled
        retentionPolicyDays
      }
    }
  }`,
  resource: 'queryazureNetworkSecurityGroup[*]',
  severity: 'medium',
  conditions: {
    path: '@.flowLogs',
    array_any: {
      and: [
        { 
          path: '[*].retentionPolicyEnabled', 
          equal: true,
        },
        {
          path: '[*].retentionPolicyDays',
          greaterThan: 90,
        }
      ],
    },
  },
}
