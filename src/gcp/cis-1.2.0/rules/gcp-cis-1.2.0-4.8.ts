export default {
  id: 'gcp-cis-1.2.0-4.8',
  description:
    'GCP CIS 4.8 Ensure Compute instances are launched with Shielded VM enabled',
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
  gql: `{
    querygcpVmInstance {
      id
      __typename
      shieldedInstanceConfig {
        enableIntegrityMonitoring
        enableVtpm
      }
     }
  }`,
  resource: 'querygcpVmInstance[*]',
  severity: 'unknown',
  conditions: {
    path: '@.shieldedInstanceConfig',
    and: [
      {
        path: '[*].enableIntegrityMonitoring',
        equal: true,
      },
      {
        path: '[*].enableVtpm',
        equal: true,
      },
    ],
  },
}
