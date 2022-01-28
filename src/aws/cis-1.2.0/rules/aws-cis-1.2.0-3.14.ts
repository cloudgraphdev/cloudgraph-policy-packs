/* eslint-disable max-len */
const filterPatternRegex =
  /\$\.eventName\s*=\s*CreateVpc.+\$\.eventName\s*=\s*DeleteVpc.+\$\.eventName\s*=\s*ModifyVpcAttribute.+\$\.eventName\s*=\s*AcceptVpcPeeringConnection.+\$\.eventName\s*=\s*CreateVpcPeeringConnection.+\$\.eventName\s*=\s*DeleteVpcPeeringConnection.+\$\.eventName\s*=\s*RejectVpcPeeringConnection.+\$\.eventName\s*=\s*AttachClassicLinkVpc.+\$\.eventName\s*=\s*DetachClassicLinkVpc.+\$\.eventName\s*=\s*DisableVpcClassicLink.+\$\.eventName\s*=\s*EnableVpcClassicLink/

export default {
  id: 'aws-cis-1.2.0-3.14',
  description:
    'AWS CIS 3.14 Ensure a log metric filter and alarm exist for VPC changes (Scored)',
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
