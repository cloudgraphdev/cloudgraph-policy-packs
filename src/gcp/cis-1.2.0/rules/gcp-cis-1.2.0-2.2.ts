export default {
  id: 'gcp-cis-1.2.0-2.2',
  description:
    'GCP CIS 2.2 Ensure that sinks are configured for all log entries',
  gql: `{
    querygcpProject {
      id
      __typename
      logSink {
        filter
      }
    }
  }`,
  resource: 'querygcpProject[*]',
  severity: 'high',
  conditions: {
    path: '@.logSink',
    array_any: {
      path: '[*].filter',
      equal: '',
    },
  },
}
