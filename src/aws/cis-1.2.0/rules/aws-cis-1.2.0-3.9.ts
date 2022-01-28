export default {
  id: 'aws-cis-1.2.0-3.9',
  description:
    'AWS CIS 3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)',
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
  gql: `{
    queryawsCloudtrail(filter: { isMultiRegionTrail: { eq: "Yes" } }) {
      id
      __typename
      isMultiRegionTrail
      status {
        isLogging
      }
      eventSelectors {
        id
        readWriteType
        includeManagementEvents
      }
      cloudwatchLog {
        arn
        metricFilters {
          id
          filterName
          filterPattern
          metricTransformations {
            metricName
          }
        }
        cloudwatch {
          metric
          arn
          actions
          sns {
            arn
            subscriptions {
              arn
            }
          }
        }
      }
    }
  }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'medium',
  conditions: {
    and: [
      {
        path: '@.isMultiRegionTrail',
        equal: 'Yes',
      },
      {
        path: '@.status.isLogging',
        equal: true,
      },
      {
        path: '@.eventSelectors',
        array_any: {
          and: [
            { path: '[*].readWriteType', equal: 'All' },
            {
              path: '[*].includeManagementEvents',
              equal: true,
            },
          ],
        },
      },
      {
        path: '@.cloudwatchLog',
        jq: '[.[].metricFilters[] + .[].cloudwatch[] | select(.metricTransformations[].metricName  == .metric)]',
        array_any: {
          and: [
            {
              and: [
                {
                  path: '[*].filterPattern',
                  match: /\s*\$.eventSource\s*=\s*config.amazonaws.com\s*/,
                },
                {
                  path: '[*].filterPattern',
                  match: /\s*\$.eventName\s*=\s*StopConfigurationRecorder\s*/,
                },
                {
                  path: '[*].filterPattern',
                  match: /\s*\$.eventName\s*=\s*DeleteDeliveryChannel\s*/,
                },
                {
                  path: '[*].filterPattern',
                  match: /\s*\$.eventName\s*=\s*PutDeliveryChannel\s*/,
                },
                {
                  path: '[*].filterPattern',
                  match: /\s*\$.eventName\s*=\s*PutConfigurationRecorder\s*/,
                },
              ],
            },
            {
              path: '[*].sns',
              array_any: {
                path: '[*].subscriptions',
                array_any: {
                  path: '[*].arn',
                  match: /^arn:aws:.*$/,
                },
              },
            },
          ],
        },
      },
    ],
  },
}
