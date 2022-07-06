// similar to CIS 6.5
export default {
  id: 'azure-nist-800-53-rev4-3.6', 
  title: 'Azure NIST 3.6 Virtual Network Network Watcher should be enabled',
  
  description: 'Enable Network Watcher for Azure subscriptions.',
  
  audit: `**From Azure Console**
  
  1. Go to Network Watcher
  2. Ensure that the STATUS is set to Enabled
  
  **Using Azure Command Line Interface 2.0**
  
      az network watcher list
  
  This will list all regions where provisioningState is Succeeded.  
  Then run
  
      az account list-locations
  
  This will list all regions that exist in the subscription. Compare this list to the previous one to Ensure that for all regions, provisioningState is set to Succeeded.`,
  
  rationale: 'Network diagnostic and visualization tools available with Network Watcher help users understand, diagnose, and gain insights to the network in Azure.',
  
  remediation: 'Opting-out of Network Watcher automatic enablement is a permanent change. Once you opt-out you cannot opt-in without contacting support.',
  
  references: [
      'https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview',
      'https://docs.azure.cn/zh-cn/cli/network/watcher?view=azure-cli-latest#az_network_watcher_list',
      'https://docs.azure.cn/zh-cn/cli/network/watcher?view=azure-cli-latest#az_network_watcher_configure',
      'https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-create',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-3-enable-logging-for-azure-network-activities',
  ],  
  severity: 'high' 
}
