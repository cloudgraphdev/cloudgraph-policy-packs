export default {
  id: 'gcp-cis-1.2.0-1.8',
  description:
    'GCP CIS 1.8 Ensure that Separation of duties is enforced while assigning service account related roles to users',
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
              match: /user.*$/,
            },
            {
              path: '[*].role',
              in: [
                'roles/iam.serviceAccountAdmin',
                'roles/iam.serviceAccountUser',
              ],
            },
          ],
        },
      },
    },
  },
}
