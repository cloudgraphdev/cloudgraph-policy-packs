export default {
  id: 'gcp-cis-1.2.0-6.4',
  description:
    'GCP CIS 6.4 Ensure that the Cloud SQL database instance requires all incoming connections to use SSL',
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
  gql: `{
    querygcpSqlInstance {
      id
      __typename
      name
      settings {
        ipConfiguration {
          requireSsl
        }
      }
    }
  }`,
  resource: 'querygcpSqlInstance[*]',
  severity: 'medium',
  conditions: {
    path: '@.settings.ipConfiguration.requireSsl',
    equal: true,
  },
}
