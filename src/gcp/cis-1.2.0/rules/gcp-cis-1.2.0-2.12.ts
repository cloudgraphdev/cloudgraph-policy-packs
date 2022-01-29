export default {
  id: 'gcp-cis-1.2.0-2.12',
  description:
    'GCP CIS 2.12 Ensure that Cloud DNS logging is enabled for all VPC networks',
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
  gql: `{
    querygcpNetwork {
      id
      __typename
      dnsPolicy {
        enableLogging
      }
    }
  }`,
  resource: 'querygcpNetwork[*]',
  severity: 'medium',
  conditions: {
    not: {
      or: [
        {
          path: '@.dnsPolicy',
          isEmpty: true,
        },
        {
          path: '@.dnsPolicy',
          array_any: {
            path: '[*].enableLogging',
            equal: false,
          },
        },
      ],
    },
  },
}
