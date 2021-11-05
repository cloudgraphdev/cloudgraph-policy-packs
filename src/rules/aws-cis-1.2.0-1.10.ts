export default {
  id: 'aws-cis-1.2.0-1.10',
  description:
    'AWS CIS 1.10 Ensure IAM password policy prevents password reuse',
  gql: `{
    queryawsIamPasswordPolicy {
      id
      __typename
      passwordReusePrevention
    }
  }`,
  resource: 'queryawsIamPasswordPolicy[*]',
  conditions: {
    path: '@.passwordReusePrevention',
    lessThan: 24,
  },
}
