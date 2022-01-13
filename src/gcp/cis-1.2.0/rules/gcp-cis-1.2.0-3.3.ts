export default {
  id: 'gcp-cis-1.2.0-3.3',
  description: 'GCP CIS 3.3 Ensure that DNSSEC is enabled for Cloud DNS',
  gql: `{
    querygcpDnsManagedZone {
      id
      __typename
      visibility
      dnssecConfigState
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
            path: '@.dnssecConfigState',
            equal: 'on',
          },
        ],
      },
    ],
  },
}
