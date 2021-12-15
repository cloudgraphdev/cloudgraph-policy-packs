export default {
  id: 'aws-cis-1.2.0-2.8',
  description:
    'AWS CIS 2.8 Ensure rotation for customer created CMKs is enabled (Scored)',
  gql: `{
    queryawsKms {
      id
      __typename
      keyManager
      keyRotationEnabled
    }
  }`,
  resource: 'queryawsKms[*]',
  severity: 'warning',
  conditions: {
    or: [
      {
        and: [
          {
            path: '@.keyManager',
            equal: 'AWS',
          },
          {
            path: '@.keyRotationEnabled',
            equal: 'Yes',
          },
        ],
      },
      {
        and: [
          {
            path: '@.keyManager',
            equal: 'CUSTOMER',
          },
          {
            path: '@.keyRotationEnabled',
            equal: 'Yes',
          },
        ],
      },
    ],
  },
}
