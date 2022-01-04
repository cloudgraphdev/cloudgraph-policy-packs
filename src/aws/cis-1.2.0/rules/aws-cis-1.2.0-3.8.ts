export default {
  id: 'aws-cis-1.2.0-3.8',
  description:
    'AWS CIS 3.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)',
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
              '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl)'
              + ' || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors)'
              + ' || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication)'
              + ' || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors)'
              + ' || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }',
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
