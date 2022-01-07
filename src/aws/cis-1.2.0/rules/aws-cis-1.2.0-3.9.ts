export default {
  id: 'aws-cis-1.2.0-3.9',
  description:
    'AWS CIS 3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)',
  gql: `{
        queryawsCloudtrail {
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
              logGroupName
            }
            cloudwatch {
              arn
              sns {
                arn
              }
            }
          }
        }
      }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'warning',
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
        array_any: {
          path: '[*].metricFilters',
          array_any: {
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
        },
      },
      {
        path: '@.cloudwatchLog',
        array_any: {
          path: '[*].cloudwatch',
          array_any: {
            path: '[*].sns',
            array_any: {
              path: '[*].subscriptions',
              array_any: {
                path: '[*].arn',
                match: /^arn:aws:.*$/,
              },
            },
          },
        },
      },
    ],
  },
}
