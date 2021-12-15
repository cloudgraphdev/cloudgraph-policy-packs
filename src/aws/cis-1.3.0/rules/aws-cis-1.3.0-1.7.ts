export default {
  id: 'aws-cis-1.3.0-1.7',
  description:
    'AWS CIS 1.7  Ensure IAM password policy requires at least one symbol',
  gql: `{
    queryawsIamPasswordPolicy {
      id
      __typename
      requireSymbols
    }
  }`,
  resource: 'queryawsIamPasswordPolicy[*]',
  severity: 'warning',
  conditions: {
    path: '@.requireSymbols',
    equal: true,
  },
}
