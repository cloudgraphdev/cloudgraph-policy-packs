export default {
  id: 'azure-cis-1.3.1-1.17',  
  title: 'Azure CIS 1.17 Ensure that \'Users can create security groups in Azure Portals\' is set to \'No\' (Manual)',  
  
  description: 'Restrict security group creation to administrators only.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Groups
  3. Go to General in setting
  4. Ensure that Users can create security groups in Azure Portals is set to No
  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,
  
  rationale: 'When creating security groups is enabled, all users in the directory are allowed to create new security groups and add members to those groups. Unless a business requires this day-to-day delegation, security group creation should be restricted to administrators only.',  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Groups
  3. Go to General in setting
  4. Set Users can create security groups in Azure Portals to No`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-accessmanagement-self-service-group-management#making-a-group-available-for-end-user-self-service',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-2-define-enterprise-segmentation-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-1-protect-and-limit-highly-privileged-users',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-5-automate-entitlement-management',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-2-restrict-administrative-access-to-business-critical-systems',
  ],  
  severity: 'low',
}
