export default {
  id: 'azure-cis-1.3.1-1.13',  
  title: 'Azure CIS 1.13 Ensure that \'Members can invite\' is set to \'No\' (Manual)',  
  
  description: 'Restrict invitations to administrators only.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to External Identities
  3. Go to External collaboration settings
  4. Ensure that Members can invite is set to No
  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,
  
  rationale: `Restricting invitations to administrators ensures that only authorized accounts have access to cloud resources. This helps to maintain "Need to Know" permissions and prevents inadvertent access to data.
  
  By default the setting Admins and users in the guest inviter role can invite is set to yes. This will allow you to use the inviter role to control who will be able to invite guests to the tenant.`,  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to External Identities
  3. Go to External collaboration settings
  4. Set Members can invite to No`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-b2b-delegate-invitations',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-2-define-enterprise-segmentation-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-5-automate-entitlement-management',
  ],  
  severity: 'high',
}
