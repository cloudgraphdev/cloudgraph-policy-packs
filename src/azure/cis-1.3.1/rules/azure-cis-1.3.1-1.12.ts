export default {
  id: 'azure-cis-1.3.1-1.12',  
  title: 'Azure CIS 1.12 Ensure that \'Guest user permissions are limited\' is set to \'Yes\' (Manual)',  
  
  description: 'Limit guest user permissions.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to External Identities
  3. Go to External collaboration settings
  4. Ensure that Guest users permissions are limited is set to Yes
  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,
  
  rationale: 'Limiting guest access ensures that guest accounts do not have permission for certain directory tasks, such as enumerating users, groups or other directory resources, and cannot be assigned to administrative roles in your directory. If guest access in not limited, they have the same access to directory data as regular users.',  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to External Identities
  3. Go to External collaboration settings
  4. Set Guest users permissions are limited to Yes`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions#member-and-guest-users',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-5-automate-entitlement-management',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-2-define-enterprise-segmentation-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
  ],  
  severity: 'high',
}
