export default {
  id: 'gcp-cis-1.2.0-1.5',
  description:
    'GCP CIS 1.5 Ensure that Service Account has no Admin privileges',
  gql: `{
    querygcpProject { 
      id 
      __typename
      iamPolicy {
        bindings {
          role
          members
       }
      }   
    }
  }`,
  resource: 'querygcpProject[*]',
  severity: 'unknown',
  conditions: {
    not: {
      path: '@.iamPolicy',
      array_any: {
        path: '[*].bindings',
        array_any: {
          and: [
            {
              path: '[*].members',
              match: /serviceAccount.*$/,
            },
            {
              or: [
                {
                  path: '[*].role',
                  in: ['roles/editor', 'roles/owner'],
                },
                {
                  path: '[*].role',
                  match: /admin.*$/gim,
                },
              ],
            },
          ],
        },
      },
    },
  },
}
