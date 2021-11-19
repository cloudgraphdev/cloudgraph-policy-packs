export default {
  id: 'aws-cis-1.2.0-1.6',
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
  severity: 'warning',
  conditions: {
    path: '@.requireLowercaseCharacters',
    equal: true,
  },
}
