export default {
  id: 'aws-cis-1.2.0-1.14',
  description:
    "AWS CIS 1.14 Ensure hardware MFA is enabled for the 'root' account (Scored)",
  gql: `{
    queryawsIamUser(filter: { name: { eq: "root" } }) {
      id
      __typename
      name
      mfaActive
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'danger',
  conditions: {
    path: '@.mfaActive',
    equal: false,
  },
}
