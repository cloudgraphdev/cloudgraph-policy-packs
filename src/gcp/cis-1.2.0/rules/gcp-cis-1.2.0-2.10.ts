/* eslint-disable max-len */
const filterPatternRegex =
  /\s*resource.type\s*=\s*gcs_bucket\s*AND\s*protoPayload.methodName\s*=\s*"storage.setIamPermissions"\s*/

export default {
  id: 'gcp-cis-1.2.0-2.10',
  description:
    'GCP CIS 2.10 Ensure that the log metric filter and alerts exist for Cloud Storage IAM permission changes',
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
