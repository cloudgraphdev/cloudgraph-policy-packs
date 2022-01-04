export default {
  id: 'aws-cis-1.2.0-3.7',
  description:
    'AWS CIS 3.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)',
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
            path: '[*].filterPattern',
            equal:
              '{($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey)||($.eventName = ScheduleKeyDeletion)) }',
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
              path: '[*].arn',
              notEqual: null,
            },
          },
        },
      },
    ],
  },
}
