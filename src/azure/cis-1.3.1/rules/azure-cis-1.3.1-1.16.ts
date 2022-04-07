export default {
  id: 'azure-cis-1.3.1-1.16',  
  title: 'Azure CIS 1.16 Ensure that \'Restrict user ability to access groups features in the Access Pane\' is set to \'No\' (Manual)',  
  
  description: 'Restrict group creation to administrators only.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Groups
  3. Go to General in setting
  4. Ensure that Restrict user ability to access groups features in the Access Pane is set to No
  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,
  
  rationale: 'Self-service group management enables users to create and manage security groups or Office 365 groups in Azure Active Directory (Azure AD). Unless a business requires this day-to-day delegation for some users, self-service group management should be disabled.',  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Groups
  3. Go to General in setting
  4. Ensure that Restrict user ability to access groups features in the Access Pane is set to No`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-accessmanagement-self-service-group-management',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-1-protect-and-limit-highly-privileged-users',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-5-automate-entitlement-management',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-2-restrict-administrative-access-to-business-critical-systems',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-2-define-enterprise-segmentation-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
  ],  
  severity: 'low',
}
