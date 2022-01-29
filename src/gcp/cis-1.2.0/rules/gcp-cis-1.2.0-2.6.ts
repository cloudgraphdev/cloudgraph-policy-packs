/* eslint-disable max-len */
const filterPatternRegex =
  /\s*resource.type\s*=\s*"iam_role"\s*AND\s*protoPayload.methodName\s*=\s*"google.iam.admin.v1.CreateRole"\s*OR\s*protoPayload.methodName\s*=\s*"google.iam.admin.v1.DeleteRole"\s*OR\s*protoPayload.methodName\s*=\s*"google.iam.admin.v1.UpdateRole"\s*/

export default {
  id: 'gcp-cis-1.2.0-2.6',
  description:
    'GCP CIS 2.6 Ensure that the log metric filter and alerts exist for Custom Role changes',
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
          filter
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
