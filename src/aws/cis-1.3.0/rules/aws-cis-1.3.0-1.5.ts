export default {
  id: 'aws-cis-1.3.0-1.5',
  description:
    'AWS CIS 1.5  Ensure IAM password policy requires at least one uppercase letter',
  gql: `{
    queryawsIamPasswordPolicy {
      id
      __typename
      requireUppercaseCharacters
    }
  }`,
  resource: 'queryawsIamPasswordPolicy[*]',
  conditions: {
    path: '@.requireUppercaseCharacters',
    equal: false,
  },
}
