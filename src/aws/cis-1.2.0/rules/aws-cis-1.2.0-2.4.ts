export default {
  id: 'aws-cis-1.2.0-2.4',
  description:
    'AWS CIS 2.4 Ensure CloudTrail trails are integrated with CloudWatch Logs',
  gql: `{
    queryawsCloudtrail {
      id
      __typename
      cloudWatchLogsLogGroupArn
      status {
        latestCloudWatchLogsDeliveryTime
      }
    }
  }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'medium',
  conditions: {
    or: [
      {
        path: '@.cloudWatchLogsLogGroupArn',
        equal: null,
      },
      {
        value: {
          daysAgo: {},
          path: '@.status.latestCloudWatchLogsDeliveryTime',
        },
        lessThanInclusive: 1,
      },
    ],
  },
}
