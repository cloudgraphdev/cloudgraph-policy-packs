export default {
  id: 'aws-cis-1.2.0-1.8',
  description:
    'AWS CIS 1.8  Ensure IAM password policy requires at least one number',
  gql: `{
    queryawsIamPasswordPolicy {
      id
      __typename
      requireNumbers
    }
  }`,
  resource: 'queryawsIamPasswordPolicy[*]',
  conditions: {
    path: '@.requireNumbers',
    equal: false,
  },
}
