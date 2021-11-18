export default {
  id: 'aws-cis-1.2.0-1.12',
  description:
    'AWS CIS 1.12  Ensure no root account access key exists (Scored)',
  gql: `{
    queryawsIamUser(filter: { name: { eq: "root" } }) {
      id
      __typename
      accessKeysActive
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'danger',
  conditions: {
    path: '@.accessKeysActive',
    equal: true,
  },
}
