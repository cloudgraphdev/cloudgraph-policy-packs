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
            // eslint-disable-next-line max-len
            match: /{\s*\(\s*\$.eventSource\s*=\s*s3.amazonaws.com\s*\)\s*&&\s*\(\s*\(\s*\$.eventName\s*=\s*PutBucketAcl\s*\)\s*||\s*\(\s*\$.eventName\s*=\s*PutBucketPolicy\s*\)\s*||\s*\(\s*\$.eventName\s*=\s*PutBucketCors\s*\)\s*||\s*\(\s*\$.eventName\s*=\s*PutBucketLifecycle\s*\)\s*||\s*\(\s*\$.eventName\s*=\s*PutBucketReplication\s*\)\s*||\s*\(\s*\$.eventName\s*=\s*DeleteBucketPolicy\s*\)\s*||\s*\(\s*\$.eventName\s*=\s*DeleteBucketCors\s*\)\s*||\s*\(\s*\$.eventName\s*=\s*DeleteBucketLifecycle\s*\)\s*||\s*\(\s*\$.eventName\s*=\s*DeleteBucketReplication\s*\)\s*\)\s*}/,
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
