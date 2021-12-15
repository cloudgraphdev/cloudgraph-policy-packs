export default {
  id: 'aws-cis-1.2.0-2.1',
  description: 'AWS CIS 2.1 Ensure CloudTrail is enabled in all regions',
  gql: `{
    queryawsCloudtrail {
      id
      __typename
      isMultiRegionTrail
      eventSelectors {
        readWriteType
        includeManagementEvents
      }
    }
  }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'warning',
  conditions: {
    or: [
      {
        path: '@.isMultiRegionTrail',
        equal: 'No',
      },
      {
        and: [
          {
            path: '@.isMultiRegionTrail',
            equal: 'Yes',
          },
          {
            path: '@.eventSelectors',
            array_any: {
              or: [
                { path: '[*].readWriteType', notEqual: 'All' },
                {
                  path: '[*].includeManagementEvents',
                  equal: false,
                },
              ],
            },
          },
        ],
      },
    ],
  },
}
