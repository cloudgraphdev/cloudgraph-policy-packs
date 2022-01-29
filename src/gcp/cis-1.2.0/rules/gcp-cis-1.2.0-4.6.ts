export default {
  id: 'gcp-cis-1.2.0-4.6',
  description:
    'GCP CIS 4.6 Ensure that IP forwarding is not enabled on Instances',
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
  gql: `{
    querygcpVmInstance{
      __typename
      id
      canIpForward
    }
  }`,
  resource: 'querygcpVmInstance[*]',
  severity: 'medium',
  conditions: {
    path: '@.canIpForward',
    equal: false,
  },
}
