export default {
  id: 'aws-cis-1.2.0-3.4',
  description:
    'AWS CIS 3.4 Ensure a log metric filter and alarm exist for IAM policy changes (Score)',
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
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*DeleteGroupPolicy/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*DeleteRolePolicy/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*DeleteUserPolicy/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*PutGroupPolicy/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*PutRolePolicy/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*PutUserPolicy/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*CreatePolicy/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*DeletePolicy/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*CreatePolicyVersion/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*DeletePolicyVersion/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*AttachRolePolicy/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*DetachRolePolicy/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*AttachUserPolicy/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*DetachUserPolicy/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*AttachGroupPolicy/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*DetachGroupPolicy/,
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
