export default {
  id: 'aws-cis-1.2.0-1.4',
  description:
    'AWS CIS 1.4 Ensure access keys are rotated every 90 days or less',
  gql: `{
    queryawsIamUser {
      id
       __typename
      accessKeyData {
        status
        lastRotated
      }
    }
  }`,
  resource: 'queryawsIamUser[*]',
  severity: 'warning',
  conditions: {
    path: '@.accessKeyData',
    array_any: {
      and: [
        {
          value: { daysAgo: {}, path: '[*].lastRotated' },
          lessThanInclusive: 90,
        },

        { path: '[*].status', equal: 'Active' },
      ],
    },
  },
}