export default {
  id: 'azure-cis-1.3.1-1.6',  
  title: 'Azure CIS 1.6 Ensure that \'Number of days before users are asked to re-confirm their authentication information\' is not set to "0" (Manual)',  
  
  description: 'Ensure that the number of days before users are asked to re-confirm their authentication information is not set to 0.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to Password reset
  4. Go to Registration
  5. Ensure that Number of days before users are asked to re-confirm their authentication information is not set to 0
  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,
  
  rationale: 'If authentication re-confirmation is disabled, registered users will never be prompted to re-confirm their existing authentication information. If the authentication information for a user, such as a phone number or email changes, then the password reset information for that user reverts to the previously registered authentication information.',  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to Password reset
  4. Go to Registration
  5. Set the Number of days before users are asked to re-confirm their authentication information to your organization defined frequency`,
  
  references: [
    'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-passwords-how-it-works#registration',
    'https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-sspr-deployment',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
  ],  
  severity: 'medium',
}
