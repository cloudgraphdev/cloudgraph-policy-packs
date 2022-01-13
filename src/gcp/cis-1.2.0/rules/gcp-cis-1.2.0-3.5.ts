export default {
  id: 'gcp-cis-1.2.0-3.5',
  description:
    'GCP CIS 3.5 Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC',
  gql: `{
    querygcpDnsManagedZone {
      id
      __typename
      visibility
      dnssecConfigDefaultKeySpecs {
        keyType
        algorithm
      }
    }
  }`,
  resource: 'querygcpDnsManagedZone[*]',
  severity: 'medium',
  conditions: {
    or: [
      {
        path: '@.visibility',
        equal: 'private',
      },
      {
        and: [
          {
            path: '@.visibility',
            equal: 'public',
          },
          {
            not: {
              path: '@.dnssecConfigDefaultKeySpecs',
              array_any: {
                and: [
                  {
                    path: '[*].keyType',
                    equal: 'zoneSigning',
                  },
                  {
                    path: '[*].algorithm',
                    equal: 'rsasha1',
                  },
                ],
              },
            },
          },
        ],
      }
    ]
  },
}
