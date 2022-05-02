export default {
  id: 'azure-cis-1.3.1-1.8',  
  title: 'Azure CIS 1.8 Ensure that \'Notify all admins when other admins reset their password?\' is set to \'Yes\' (Manual)',  
  
  description: 'Ensure that all administrators are notified if any other administrator resets their password.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to Password reset
  4. Go to Notification
  5. Ensure that notify all admins when other admins reset their password? is set to Yes
  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,
  
  rationale: 'Administrator accounts are sensitive. Any password reset activity notification, when sent to all administrators, ensures that all administrators can passively confirm if such a reset is a common pattern within their group. For example, if all administrators change their password every 30 days, any password reset activity before that may require administrator(s) to evaluate any unusual activity and confirm its origin.',  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to Password reset
  4. Go to Notification
  5. Set Notify all admins when other admins reset their password? to Yes`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-passwords-how-it-works#notifications',
      'https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-sspr-deployment',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-1-protect-and-limit-highly-privileged-users',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-2-restrict-administrative-access-to-business-critical-systems',
  ],  
  severity: 'high',
}
