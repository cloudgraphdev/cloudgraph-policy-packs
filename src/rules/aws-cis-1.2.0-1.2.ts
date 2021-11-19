export default {
  id: 'aws-cis-1.2.0-1.2',
  description:
    'AWS CIS 1.2 Ensure MFA is enabled for all IAM users that have a console password (Scored)',
  gql: `{
    queryawsIamUser {
      id
      __typename
      passwordEnabled
      mfaActive
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'warning',
  conditions: {
    and: [
      {
        path: '@.passwordEnabled',
        equal: true,
      },
      {
        path: '@.mfaActive',
        equal: true,
      },
    ],
  },
}
