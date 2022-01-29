export default {
  id: 'gcp-cis-1.2.0-3.8',
  description:
    'GCP CIS 3.8 Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network',
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
  gql: `{
    querygcpNetwork{
      id
      __typename
      subnet{
        purpose
        enableFlowLogs
      }
    }
  }`,
  resource: 'querygcpNetwork[*]',
  severity: 'high',
  conditions: {
    path: '@.subnet',
    array_all: {
      or: [
        {
          path: '[*].purpose',
          notEqual: 'PRIVATE',
        },
        {
          and: [
            {
              path: '[*].purpose',
              equal: 'PRIVATE',
            },
            {
              path: '[*].enableFlowLogs',
              equal: true,
            },
          ],
        },
      ],
    },
  },
}
