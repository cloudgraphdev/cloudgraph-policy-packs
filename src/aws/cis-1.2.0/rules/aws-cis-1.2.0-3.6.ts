export default {
  id: 'aws-cis-1.2.0-3.6',
  description:
    'AWS CIS 3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)',
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
            match: /{\s*\(\s*\$.eventName\s*=\s*ConsoleLogin\s*\)\s*&&\s*\(\s*\$.errorMessage\s*=\s*"Failed authentication"\s*\)\s*\}/,
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
              match: /^arn:aws:.*$/,
            },
          },
        },
      },
    ],
  },
}
