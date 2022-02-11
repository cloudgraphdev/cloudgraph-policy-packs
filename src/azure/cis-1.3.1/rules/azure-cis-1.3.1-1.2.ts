export default {
  id: 'azure-cis-1.3.1-1.2',  
  title: 'Azure CIS 1.2 Ensure that multi-factor authentication is enabled for all non-privileged users (Manual)',  
  description: 'Enable multi-factor authentication for all non-privileged users.',  
  audit: `**From Azure Console**

  1. Go to Azure Active Directory
  2. Go to Users
  3. Go to All Users
  4. Click on Multi-Factor Authentication button on the top bar
  5. Ensure that for all users MULTI-FACTOR AUTH STATUS is Enabled

  **Microsoft Graph API**  
  For Every Subscription, For Every Tenant  
  **Step 1:** Identify Users with non-administrative Access

  1. List All Users Using Microsoft Graph API:

          GET https://graph.microsoft.com/v1.0/users

  Capture id and corresponding userPrincipalName ($uid, $userPrincipalName)

  2. List all Role Definitions Using Azure management API:

          https://management.azure.com/subscriptions/:subscriptionId/providers/Microsoft.Authorization/roleDefinitions?api-version=2017-05-01

  Capture Role Definition IDs/Name ($name) and role names ($properties/roleName) where "properties/roleName" does NOT contain (Owner or *contributor or admin )

  3. List All Role Assignments (Mappings $A.uid to $B.name) Using Azure Management API:

          GET https://management.azure.com/subscriptions/:subscriptionId/providers/Microsoft.Authorization/roleassignments?api-version=2017-10-01-preview

  Find all non-administrative roles ($B.name) in "Properties/roleDefinationId" mapped with user ids ($A.id) in "Properties/principalId" where "Properties/principalType" == "User"  
  D> Now Match ($CProperties/principalId) with $A.uid and get $A.userPrincipalName save this as D.userPrincipleName

  **Step 2:** Run MSOL Powershell command:

          Get-MsolUser -All | where {$_.StrongAuthenticationMethods.Count -eq 0} | Select-Object -Property UserPrincipalName

  If the output contains any of the $D.userPrincipleName, then this recommendation is non-compliant.  
  _Please note that at this point of time, there is no API/CLI mechanism available to programmatically conduct security assessment for this recommendation. Only option is MSOL_`,

  rationale:'Multi-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk.',

  remediation: 'Follow Microsoft Azure documentation and setup multi-factor authentication in your environment. https://docs.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-azure-mfa',  
  references: [
      'https://docs.microsoft.com/en-us/azure/multi-factor-authentication/multi-factor-authentication',
      'https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-identity-management#im-4-use-strong-authentication-controls-for-all-azure-active-directory-based-access',
  ],  
  severity: 'high',
}
