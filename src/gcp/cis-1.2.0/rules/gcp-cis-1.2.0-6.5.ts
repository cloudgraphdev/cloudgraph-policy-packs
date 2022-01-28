export default {
  id: 'gcp-cis-1.2.0-6.5',
  description:
    'GCP CIS 6.5 Ensure that Cloud SQL database instances are not open to the world',
  gql: `{
    querygcpSqlInstance {
      id
      __typename
      name
      settings {
        ipConfiguration {
          authorizedNetworks {
            value
          }
        }
      }
    }
  }`,
  resource: 'querygcpSqlInstance[*]',
  severity: 'high',
  conditions: {
    path: '@.settings.ipConfiguration.authorizedNetworks',
    array_all: {
      path: '[*].value',
      notEqual: '0.0.0.0/0',
    },
  },
}
