export default {
  id: 'gcp-cis-1.2.0-3.2',
  description: 'GCP CIS 3.2 Ensure legacy networks do not exist for a project',
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
  gql: `{
    querygcpNetwork {
      id
      __typename
      ipV4Range
    }
  }`,
  resource: 'querygcpNetwork[*]',
  severity: 'medium',
  conditions: {
    path: '@.ipV4Range',
    equal: null,
  },
}
