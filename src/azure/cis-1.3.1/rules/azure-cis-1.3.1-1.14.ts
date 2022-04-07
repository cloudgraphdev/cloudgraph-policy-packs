export default {
  id: 'azure-cis-1.3.1-1.14',  
  title: 'Azure CIS 1.14 Ensure that \'Guests can invite\' is set to \'No\' (Manual)',  
  
  description: 'Restrict guest being able to invite other guests to collaborate with your organization.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to External Identities
  3. Go to External collaboration settings
  4. Ensure that Guests can invite is set to No
  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,
  
  rationale: 'Restricting invitations to administrators ensures that only authorized accounts have access to cloud resources. This helps to maintain "Need to Know" permissions and prevents inadvertent access to data.',  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to External Identities
  3. Go to External collaboration settings
  4. Set Guests can invite to No`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-b2b-delegate-invitations',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-1-protect-and-limit-highly-privileged-users',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-5-automate-entitlement-management',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-2-restrict-administrative-access-to-business-critical-systems',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-2-define-enterprise-segmentation-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
  ],  
  severity: 'high',
}
