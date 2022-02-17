export default {
  id: 'azure-cis-1.3.1-1.3',  
  title: 'Azure CIS 1.3 Ensure guest users are reviewed on a monthly basis',  
  
  description: `Azure AD is extended to include Azure AD B2B collaboration, allowing you to invite people from outside your organization to be guest users in your cloud account and sign in with their own work, school, or social identities. Guest users allow you to share your company's applications and services with users from any other organization, while maintaining control over your own corporate data.
  
  Work with external partners, large or small, even if they don't have Azure AD or an IT department. A simple invitation and redemption process lets partners use their own credentials to access your company's resources a a guest user.`,
  
  audit: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users and group
  3. Go to All Users
  4. Click on Show drop down and select Guest users only
  5. Ensure that guest users listed are still required (USER TYPE = Guest)
  
  **Using Azure Command Line Interface 2.0**
  
      az ad user list --query "[?userType=='Guest']"
  
  Ensure all users listed are not inactive and still required.
  
  **Using PowerShell**
  
      Connect-AzureAD (Only needs to be performed once within the PowerShell session)
      Get-AzureADUser |Where-Object {$_.UserType -like "Guest"} |Select-Object DisplayName, UserPrincipalName, UserType -Unique`,
  
  rationale: `Guest users in the Azure AD are generally required for collaboration purposes in Office 365, and may also be required for Azure functions in enterprises with multiple Azure tenants, Guest users should be reviewed on a regular basis, at least annually, Guest users should not be granted administrative roles where possible.
  
  Guest users are typically added outside your employee on-boarding/off-boarding process and could potentially be overlooked indefinitely leading to a potential vulnerability.
  
  Guest users should be review on a monthly basis to ensure that inactive and unneeded accounts are removed.`,  
  
  remediation: `**From Azure Console**
  
  1. Go to Azure Active Directory
  2. Go to Users and group
  3. Go to All Users
  4. Click on Show drop down and select Guest users only
  5. Delete all "Guest" users that are no longer required or are inactive.
  
  It is good practice to use a dynamic group to manage guest users. To create the dynamic group:
  
  1. Navigate to the Active Directory blade in the Azure Portal
  2. Select the Groups item
  3. Create new
  4. Type of dynamic
  5. Use the following dynamic selection rule. "(user.userType -eq "Guest")"
  6. Once the group has been created, select access reviews option and create a new access review with a period of monthly and send to relevant administrators for review.`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/active-directory/b2b/user-properties',
      'https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/add-users-azure-active-directory#delete-a-user',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-3-review-and-reconcile-user-access-regularly',
  ],  
  gql: `{
    queryazureADUser {
      id
      __typename
      userType
      accountEnabled
      createdDateTime
    }
  }`,
  resource: 'queryazureADUser[*]',
  severity: 'high',
  conditions: {
    not: {
      and: [
        {
          path: '@.userType',
          equal: 'Guest'
        },
        {
          or : [
            {
              path: '@.accountEnabled',
              notEqual: true
            },
            {
              value: { daysAgo: {}, path: '@.createdDateTime' },
              greaterThan: 30,
            }
          ]
        },
      ],
    },
  },
}
