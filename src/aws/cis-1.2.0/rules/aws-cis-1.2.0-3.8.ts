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
            and: [
              {
                path: '[*].filterPattern',
                match: /\s*\$.eventSource\s*=\s*s3.amazonaws.com\s*/,
              },
              {
                path: '[*].filterPattern',
                match: /\s*\$.eventName\s*=\s*PutBucketAcl\s*/,
              },
              {
                path: '[*].filterPattern',
                match: /\s*\$.eventName\s*=\s*PutBucketPolicy\s*/,
              },
              {
                path: '[*].filterPattern',
                match: /\s*\$.eventName\s*=\s*PutBucketCors\s*/,
              },
              {
                path: '[*].filterPattern',
                match: /\s*\$.eventName\s*=\s*PutBucketLifecycle\s*/,
              },
              {
                path: '[*].filterPattern',
                match: /\s*\$.eventName\s*=\s*PutBucketReplication\s*/,
              },
              {
                path: '[*].filterPattern',
                match: /\s*\$.eventName\s*=\s*DeleteBucketPolicy\s*/,
              },
              {
                path: '[*].filterPattern',
                match: /\s*\$.eventName\s*=\s*DeleteBucketCors\s*/,
              },
              {
                path: '[*].filterPattern',
                match: /\s*\$.eventName\s*=\s*DeleteBucketLifecycle\s*/,
              },
              {
                path: '[*].filterPattern',
                match: /\s*\$.eventName\s*=\s*DeleteBucketReplication\s*/,
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
