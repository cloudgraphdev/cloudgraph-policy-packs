/* eslint-disable max-len */
const filterPatternRegex =
  /\s*protoPayload.methodName\s*=\s*"SetIamPolicy"\s*AND\s*protoPayload.serviceData.policyDelta.auditConfigDeltas:*\s*/

export default {
  id: 'gcp-cis-1.2.0-2.5',
  description:
    'GCP CIS 2.5 Ensure that the log metric filter and alerts exist for Audit Configuration changes',
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
