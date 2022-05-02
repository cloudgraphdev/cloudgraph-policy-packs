export default {
  id: 'azure-cis-1.3.1-1.7',  
  title: 'Azure CIS 1.7 Ensure that \'Notify users on password resets?\' is set to \'Yes\' (Manual)',  
  
  description: 'Ensure that users are notified on their primary and secondary emails on password resets.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to Password reset
  4. Go to Notification
  5. Ensure that Notify users on password resets? is set to Yes
  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,
  
  rationale: 'User notification on password reset is a passive way of confirming password reset activity. It helps the user to recognize unauthorized password reset activities.',  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to Password reset
  4. Go to Notification
  5. Set Notify users on password resets? to Yes`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-passwords-how-it-works#notifications',
      'https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-sspr-deployment',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
  ],  
  severity: 'medium',
}
