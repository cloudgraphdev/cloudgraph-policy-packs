export default {
  id: 'aws-cis-1.3.0-1.13',
  description: "AWS CIS 1.13 Ensure MFA is enabled for the 'root' account",
  gql: `{
    queryawsIamUser(filter: { name: { eq: "root" } }) {
      id
      __typename
      name
      mfaActive
    }
  }`,
  resource: 'queryawsIamUser[*]',
  conditions: {
    path: '@.mfaActive',
    equal: false,
  },
}
