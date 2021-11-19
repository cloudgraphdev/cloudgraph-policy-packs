export default {
  id: 'aws-cis-1.3.0-1.6',
  description:
    'AWS CIS 1.6  Ensure IAM password policy requires at least one lowercase letter',
  gql: `{
    queryawsIamPasswordPolicy {
      id
      __typename
      requireLowercaseCharacters
    }
  }`,
  resource: 'queryawsIamPasswordPolicy[*]',
  conditions: {
    path: '@.requireLowercaseCharacters',
    equal: false,
  },
}
