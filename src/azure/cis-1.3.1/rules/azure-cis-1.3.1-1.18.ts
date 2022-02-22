export default {
  id: 'azure-cis-1.3.1-1.18',  
  title: 'Azure CIS 1.18 Ensure that \'Owners can manage group membership requests in the Access Panel\' is set to \'No\' (Manual)',  
  
  description: 'Restrict security group management to administrators only.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Groups
  3. Go to General in settings
  4. Ensure that Owners can manage group membership requests in the Access Panel is set to No
  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,
  
  rationale: 'Restricting security group management to administrators only prohibits users from making changes to security groups. This ensures that security groups are appropriately managed and their management is not delegated to non-administrators.',  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Groups
  3. Go to General in settings
  4. Set Owners can manage group membership requests in the Access Panel to No`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-accessmanagement-self-service-group-management#making-a-group-available-for-end-user-self-service',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-1-protect-and-limit-highly-privileged-users',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-5-automate-entitlement-management',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-8-choose-approval-process-for-microsoft-support',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-2-define-enterprise-segmentation-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
  ],  
  severity: 'low',
}
