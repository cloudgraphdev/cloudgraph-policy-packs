export default {
  id: 'azure-cis-1.3.1-1.19',  
  title: 'Azure CIS 1.19 Ensure that \'Users can create Microsoft 365 groups in Azure Portals\' is set to \'No\' (Manual)',  
  
  description: 'Restrict Microsoft 365 group creation to administrators only.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Groups
  3. Go to General in setting
  4. Ensure that Users can create Microsoft 365 groups in Azure Portals is set to No
  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,
  
  rationale: 'Restricting Microsoft 365 group creation to administrators only ensures that creation of Microsoft 365 groups is controlled by the administrator. Appropriate groups should be created and managed by the administrator and group creation rights should not be delegated to any other user.',  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Groups
  3. Go to General in setting
  4. Set Users can create Microsoft 365 groups in Azure Portals to No`,
  
  references: [
      'https://whitepages.unlimitedviz.com/2017/01/disable-office-365-groups-2/',
      'https://support.office.com/en-us/article/Control-who-can-create-Office-365-Groups-4c46c8cb-17d0-44b5-9776-005fced8e618',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-2-define-enterprise-segmentation-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-1-protect-and-limit-highly-privileged-users',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-5-automate-entitlement-management',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-2-restrict-administrative-access-to-business-critical-systems',
  ],  
  severity: 'low',
}
