export default {
  id: 'pci-dss-3.2.1-user-check-1',  
  title: 'User Check 1: Active Directory custom subscription owner roles should not be created',
  
  description: 'Subscription ownership should not include permission to create custom owner roles. The principle of least privilege should be followed and only necessary privileges should be assigned instead of allowing full administrative access.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**From Azure Console**
  
  - Navigate to [Roles and administrators](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RolesAndAdministrators).
  - Select the custom role.
  - Click the ellipsis (…) and click Delete.
  
  **Using Command Line:**
  
  - Get the list of Azure roles:
  
          az role definition list
  
  - Check for entries with assignableScope of / or a subscription, and an action of *
  
    - Verify the usage and impact of removing the role:
  
          az role definition delete --name "rolename"`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/role-based-access-control/custom-roles-portal',
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
