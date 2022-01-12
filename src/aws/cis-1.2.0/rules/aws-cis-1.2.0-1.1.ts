export default {
  id: 'aws-cis-1.2.0-1.1',
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
  severity: 'high',
  conditions: {
    not: {
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
  },
}
