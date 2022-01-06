export default {
  id: 'aws-cis-1.2.0-3.2',
  description:
    'AWS CIS 3.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)',
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
        }
        cloudwatch {
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
                match: /(\$.errorCode)\s*=\s*"ConsoleLogin"/

              },
              {
                path: '[*].filterPattern',
                match: /(\$.additionalEventData.MFAUsed)\s*!=\s*"Yes"/
              }
            ]
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
                notEqual: null,
              },
            },
          },
        },
      },
    ],
  },
}
