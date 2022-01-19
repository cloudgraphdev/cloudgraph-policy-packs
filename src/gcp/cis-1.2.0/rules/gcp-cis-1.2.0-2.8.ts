/* eslint-disable max-len */
const filterPatternRegex =
  /\s*resource.type\s*=\s*"gce_route"\s*AND\s*protoPayload.methodName\s*=\s*"beta.compute.routes.patch"\s*OR\s*protoPayload.methodName\s*=\s*"beta.compute.routes.insert"\s*/

export default {
  id: 'gcp-cis-1.2.0-2.8',
  description:
    'GCP CIS 2.8 Ensure that the log metric filter and alerts exist for VPC network route changes',
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
