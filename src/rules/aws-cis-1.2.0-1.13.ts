export default {
  id: 'aws-cis-1.2.0-1.13',
  description: "AWS CIS 1.13 Ensure MFA is enabled for the 'root' account",
  gql: `{
    queryawsIamUser {
      id
      __typename
      name
      mfaActive
    }
  }`,
  resource: 'queryawsIamUser[*]',
  conditions: {
    and: [
      {
        path: '@.mfaActive',
        equal: false,
      },
      {
        path: '@.name',
        equal: 'root',
      },
    ],
  },
}
