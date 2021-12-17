export default {
  id: 'aws-cis-1.3.0-1.1',
  description:
    "AWS CIS 1.1 Avoid the use of 'root' account. Show used in last 30 days (Scored)",
  gql: `{
    queryawsIamUser(filter: { name: { eq: "root" } }) {
      id
      __typename
      passwordLastUsed
      passwordEnabled
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'danger',
  conditions: {
    and: [
      {
        path: '@.passwordEnabled',
        equal: true,
      },
      {
        value: { daysAgo: {}, path: '@.passwordLastUsed' },
        lessThanInclusive: 30,
      },
    ],
  },
}