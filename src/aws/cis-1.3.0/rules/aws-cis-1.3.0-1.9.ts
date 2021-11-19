export default {
  id: 'aws-cis-1.3.0-1.9',
  description:
    'AWS CIS 1.9 Ensure IAM password policy requires minimum length of 14 or greater',
  gql: `{
    queryawsIamPasswordPolicy {
      id
      __typename
      minimumPasswordLength
    }
  }`,
  resource: 'queryawsIamPasswordPolicy[*]',
  conditions: {
    path: '@.minimumPasswordLength',
    lessThan: 14,
  },
}
