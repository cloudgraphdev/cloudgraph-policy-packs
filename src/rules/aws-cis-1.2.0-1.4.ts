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
        lastUsedDate
      }
    }
  }`,
  resource: 'queryawsIamUser[*]',
  conditions: {
    and: [
      {
        path: '@.accessKeyData',
        array_any: {
          value: { daysAgo: {}, path: '[*].lastUsedDate' },
          greaterThan: 90,
        },
      },
      {
        path: '@.accessKeyData',
        array_any: { equal: 'Active', path: '[*].status' },
      },
    ],
  },
}
