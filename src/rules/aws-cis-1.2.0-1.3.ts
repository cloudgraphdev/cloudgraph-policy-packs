export default {
  id: 'aws-cis-1.2.0-1.3',
  description:
    'AWS CIS 1.3 Ensure credentials unused for 90 days or greater are disabled',
  gql: `{
   queryawsIamUser {
      id
      __typename
      passwordLastUsed
      accessKeyData {
        lastUsedDate
      }
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'warning',
  conditions: {
    or: [
      {
        value: { daysAgo: {}, path: '@.passwordLastUsed' },
        lessThanInclusive: 90,
      },
      {
        path: '@.accessKeyData',
        array_any: {
          value: { daysAgo: {}, path: '[*].lastUsedDate' },
          lessThanInclusive: 90,
        },
      },
    ],
  },
}
