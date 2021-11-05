export default {
  id: 'aws-cis-1.2.0-1.9',
  description:
    'AWS CIS 1.9 Ensure IAM password policy requires minimum length of 14 or greater',
  gql: `{
    queryawsIamPasswordPolicy {
      id
      __typename
      minimumPasswordLength
    }
  }`,
  rationale: 'not good',
  resource: 'queryawsIamPasswordPolicy[*]',
  conditions: {
    path: '@.minimumPasswordLength',
    lessThanInclusive: 14,
  },
}
