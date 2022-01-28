/* eslint-disable max-len */
const filterPatternRegex =
  /\$\.eventName\s*=\s*CreateRoute.+\$\.eventName\s*=\s*CreateRouteTable.+\$\.eventName\s*=\s*ReplaceRoute.+\$\.eventName\s*=\s*ReplaceRouteTableAssociation.+\$\.eventName\s*=\s*DeleteRouteTable.+\$\.eventName\s*=\s*DeleteRoute.+\$\.eventName\s*=\s*DisassociateRouteTable/

export default {
  id: 'aws-cis-1.2.0-3.13',
  description:
    'AWS CIS 3.13 Ensure a log metric filter and alarm exist for route table changes (Scored)',
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
              path: '[*].filterPattern',
              match: filterPatternRegex,
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
