export default {
  id: 'azure-cis-1.3.1-1.10',  
  title: 'Azure CIS 1.10 Ensure that \'Users can add gallery apps to their Access Panel\' is set to \'No\' (Manual)',  
  
  description: 'Require administrators to provide consent for the apps before use.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to User settings
  4. Click on Manage how end users launch and view their applications
  5. Ensure that Users can add gallery apps to their Access Panel is set to No
  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,
  
  rationale: 'Unless Azure Active Directory is running as an identity provider for third-party applications, do not allow users to use their identity outside of your cloud environment. User profiles contain private information such as phone numbers and email addresses which could then be sold off to other third parties without requiring any further consent from the user.',  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to User settings
  4. Click on Manage how end users launch and view their applications
  5. Set Users can add gallery apps to their Access Panel to No`,
  
  references: [
      'https://blogs.msdn.microsoft.com/exchangedev/2014/06/05/managing-user-consent-for-applications-using-office-365-apis/',
      'https://nicksnettravels.builttoroam.com/post/2017/01/24/Admin-Consent-for-Permissions-in-Azure-Active-Directory.aspx',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-1-define-asset-management-and-data-protection-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-1-protect-and-limit-highly-privileged-users',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-2-restrict-administrative-access-to-business-critical-systems',
  ],  
  severity: 'medium',
}
