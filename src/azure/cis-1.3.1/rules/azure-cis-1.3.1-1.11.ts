export default {
  id: 'azure-cis-1.3.1-1.11',  
  title: 'Azure CIS 1.11 Ensure that \'Users can register applications\' is set to \'No\' (Manual)',  
  
  description: 'Require administrators to register third-party applications.',
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to User settings
  4. Ensure that Users can register applications is set to No
  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation._
  
  **Using PowerShell**
  
      Connect-MsolService
      Get-MsolCompanyInformation | Select-Object
      UsersPermissionToCreateLOBAppsEnabled
  
  Command should return UsersPermissionToCreateLOBAppsEnabled with the value of False`,
  
  rationale: 'It is recommended to let administrator register custom-developed applications. This ensures that the application undergoes a security review before exposing active directory data to it.',  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to User settings
  4. Set Users can register applications to No`,
  
  references: [
      'https://blogs.msdn.microsoft.com/exchangedev/2014/06/05/managing-user-consent-for-applications-using-office-365-apis/',
      'https://nicksnettravels.builttoroam.com/post/2017/01/24/Admin-Consent-for-Permissions-in-Azure-Active-Directory.aspx',
      'https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-how-applications-are-added#who-has-permission-to-add-applications-to-my-azure-ad-instance',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-1-define-asset-management-and-data-protection-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-1-protect-and-limit-highly-privileged-users',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-2-restrict-administrative-access-to-business-critical-systems',
  ],  
  severity: 'medium',
}
