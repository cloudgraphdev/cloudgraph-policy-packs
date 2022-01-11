export default {
  id: 'aws-cis-1.2.0-1.16',
  description:
    'AWS CIS 1.16 Ensure IAM policies are attached only to groups or roles (Scored)',
  gql: `{
    queryawsIamUser {
      id
      __typename
      iamAttachedPolicies {
        name
      },
      inlinePolicies
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.iamAttachedPolicies',
        isEmpty: true,
      },
      {
        path: '@.inlinePolicies',
        isEmpty: true,
      },
    ],
  },
}
