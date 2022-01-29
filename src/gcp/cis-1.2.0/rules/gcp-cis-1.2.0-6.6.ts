export default {
  id: 'gcp-cis-1.2.0-6.6',
  description:
    'GCP CIS 6.6 Ensure that Cloud SQL database instances do not have public IPs',
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
  gql: `{
    querygcpSqlInstance(filter:{instanceType:{eq: "CLOUD_SQL_INSTANCE"}, backendType:{eq: "SECOND_GEN"}}) {
      id
      __typename
      name
      ipAddresses{
        type
      }
    }
  }`,
  resource: 'querygcpSqlInstance[*]',
  severity: 'unknown',
  conditions: {
    path: '@.ipAddresses',
    array_all: {
      path: '[*].type',
      equal: 'PRIVATE',
    },
  },
}
