export default {
  id: 'azure-cis-1.3.1-1.21',  
  title: 'Azure CIS 1.21 Ensure that no custom subscription owner roles are created',  
  
  description: 'Subscription ownership should not include permission to create custom owner roles. The principle of least privilege should be followed and only necessary privileges should be assigned instead of allowing full administrative access.',
  
  audit: `**Using Azure Command Line Interface 2.0**
  
      az role definition list
  
  Check for entries with assignableScope of / or a subscription, and an action of * Verify the usage and impact of removing the role identified
  
  **Using PowerShell**
  
      Connect-AzAccount Get-AzRoleDefinition |Where-Object {($.IsCustom -eq $true) -and ($.Name -like "Owner")}
  
  Review output for each returned role's 'AssignableScopes' value for '/' or the current subscription, and 'Actions' containing the '*' wildcard character.`,
  
  rationale: 'Classic subscription admin roles offer basic access management and include Account Administrator, Service Administrator, and Co-Administrators. It is recommended the least necessary permissions be given initially. Permissions can be added as needed by the account holder. This ensures the account holder cannot perform actions which were not intended.',  
  
  remediation: `**Using Azure Command Line Interface 2.0**
  
      az role definition list
  
  Check for entries with assignableScope of / or a subscription, and an action of * Verify the usage and impact of removing the role identified
  
      az role definition delete --name "rolename"`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/billing/billing-add-change-azure-subscription-administrator',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-2-define-enterprise-segmentation-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-1-protect-and-limit-highly-privileged-users',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-5-automate-entitlement-management',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-2-restrict-administrative-access-to-business-critical-systems',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-2-define-enterprise-segmentation-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-governance-strategy#gs-6-define-identity-and-privileged-access-strategy',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-privileged-access#pa-7-follow-just-enough-administration-least-privilege-principle',
  ],  
  gql: `{
    queryazureAuthRoleDefinition {
      id
      __typename
      assignableScopes
      permissions {
        actions
      }
    }
  }`,
  resource: 'queryazureAuthRoleDefinition[*]',
  severity: 'high',
  conditions: {
    not: {
      and: [
        {
          path: '@.assignableScopes',
          array_any: {
            or: [
              {
                path: '[*]',
                equal: '/',
              },
              {
                path: '[*]',
                match: /subscriptions/,
              },
            ],
          },
        },
        {
          path: '@.permissions',
          array_any: {
            path: '[*].actions',
            array_any: {
              path: '[*]',
              equal: '*',
            },
          },
        },
      ],
    },
  },
}
