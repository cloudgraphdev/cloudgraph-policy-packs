export default {
  id: 'azure-cis-1.3.1-1.15',  
  title: 'Azure CIS 1.15 Ensure that \'Restrict access to Azure AD administration portal\' is set to \'Yes\' (Manual)',  
  
  description: 'Restrict access to the Azure AD administration portal to administrators only.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to User settings
  4. Ensure that Restrict access to Azure AD administration portal is set to Yes
  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,
  
  rationale: 'The Azure AD administrative portal has sensitive data. All non-administrators should be prohibited from accessing any Azure AD data in the administration portal to avoid exposure.',  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to User settings
  4. Set Restrict access to Azure AD administration portal to Yes`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-assign-admin-roles-azure-portal',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-2-define-enterprise-segmentation-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-1-protect-and-limit-highly-privileged-users',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-2-restrict-administrative-access-to-business-critical-systems',
  ],  
  severity: 'low',
}
