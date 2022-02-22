export default {
  id: 'azure-cis-1.3.1-1.20',  
  title: 'Azure CIS 1.20 Ensure that \'Require Multi-Factor Auth to join devices\' is set to \'Yes\' (Manual)',  
  
  description: 'Joining devices to the active directory should require Multi-factor authentication.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Devices
  3. Go to Device settings
  4. Ensure that Require Multi-Factor Auth to join devices is set to Yes
  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._`,
  
  rationale: 'Multi-factor authentication is recommended when adding devices to Azure AD. When set to "Yes", users who are adding devices from the internet must first use the second method of authentication before their device is successfully added to the directory. This ensures that rogue devices are not added to the directory for a compromised user account.',  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Devices
  3. Go to Device settings
  4. Set Require Multi-Factor Auth to join devices to Yes`,
  
  references: [
      'https://blogs.technet.microsoft.com/janketil/2016/02/29/azure-mfa-for-enrollment-in-intune-and-azure-ad-device-registration-explained/',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-identity-management#im-4-use-strong-authentication-controls-for-all-azure-active-directory-based-access',
  ],  
  severity: 'medium',
}
