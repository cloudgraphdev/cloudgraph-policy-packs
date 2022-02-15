export default {
  id: 'azure-cis-1.3.1-1.5',  
  title: 'Azure CIS 1.5 Ensure that \'Number of methods required to reset\' is set to \'2\' (Manual)',  
  
  description: 'Ensure that two alternate forms of identification are provided before allowing a password reset.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to Password reset
  4. Go to Authentication methods
  5. Ensure that Number of methods required to reset is set to 2
  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,
  
  rationale: 'Like multi-factor authentication, setting up dual identification before allowing a password reset ensures that the user identity is confirmed via two separate forms of identification. With dual identification set, an attacker would require compromising both the identity forms before he/she could maliciously reset a user\'s password.',  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to Password reset
  4. Go to Authentication methods
  5. Set the Number of methods required to reset to 2`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-passwords-faq#password-reset-registration',
      'https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-sspr-deployment',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-identity-management#im-4-use-strong-authentication-controls-for-all-azure-active-directory-based-access',
  ],
  severity: 'high',
}
