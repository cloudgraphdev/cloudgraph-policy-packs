export default {
  id: 'gcp-cis-1.2.0-1.6',
  description:
    'GCP CIS 1.6 Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level',
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
                'roles/iam.serviceAccountUser',
                'roles/iam.serviceAccountTokenCreator',
              ],
            },
          ],
        },
      },
    },
  },
}
