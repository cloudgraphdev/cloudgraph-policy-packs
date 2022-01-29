/* eslint-disable max-len */
const filterPatternRegex =
  /\s*protoPayload.methodName\s*=\s*"cloudsql.instances.update"\s*/

export default {
  id: 'gcp-cis-1.2.0-2.11',
  description:
    'GCP CIS 2.11 Ensure that the log metric filter and alerts exist for SQL instance configuration changes',
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
  gql: `{
    querygcpAlertPolicy {
      id
      __typename
      enabled {
        value
      }
      project {
        logMetric {
          name
          filter
          metricDescriptor {
            type
          }
        }
      }
    }
  }`,
  resource: 'querygcpAlertPolicy[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.enabled.value',
        equal: true,
      },
      {
        path: '@.project',
        jq: '[.[].logMetric[] | select( "logging.googleapis.com/user/" + .name == .metricDescriptor.type)]',
        array_any: {
          path: '[*].filter',
          match: filterPatternRegex,
        },
      },
    ],
  },
}
