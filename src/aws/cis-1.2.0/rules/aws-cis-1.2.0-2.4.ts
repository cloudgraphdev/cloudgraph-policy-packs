export default {
  id: 'aws-cis-1.2.0-2.4',
  description:
    'AWS CIS 2.4 Ensure CloudTrail trails are integrated with CloudWatch Logs',
  audit: `Perform the following to ensure CloudTrail is configured as prescribed:
  Via the AWS management Console
  
  1. Sign in to the AWS Management Console and open the CloudTrail console at https://console.aws.amazon.com/cloudtrail/
  2. Under All Buckets , click on the target bucket you wish to evaluate
  3. Click Properties on the top right of the console
  4. Click Trails in the left menu
  5. Ensure a CloudWatch Logs log group is configured and has a recent (~one day old) Last log file delivered timestamp.
  
  Via CLI
  1. Run the following command to get a listing of existing trails:
  
  aws cloudtrail describe-trails
  
  2. Ensure CloudWatchLogsLogGroupArn is not empty and note the value of the Name
      property.
  3. Using the noted value of the Name property, run the following command:
  
  aws cloudtrail get-trail-status --name <trail_name>
  
  4. Ensure the LatestcloudwatchLogdDeliveryTime property is set to a recent (~one day old) timestamp.`,
  rationale: `Sending CloudTrail logs to CloudWatch Logs will facilitate real-time and historic activity logging based on user, API, resource, and IP address, and provides the opportunity to establish alarms and notifications for anomalous or sensitivity account activity.`,
  remediation: `Perform the following to establish the prescribed state:
  Via the AWS management Console
  
  1. Sign in to the AWS Management Console and open the CloudTrail console at https://console.aws.amazon.com/cloudtrail/
  2. Under All Buckets, click on the target bucket you wish to evaluate
  3. Click Properties on the top right of the console
  4. Click Trails in the left menu
  5. Click on each trail where no CloudWatch Logs are defined
  6. Go to the CloudWatch Logs section and click on Configure
  7. Define a new or select an existing log group
  8. Click on Continue
  9. Configure IAM Role which will deliver CloudTrail events to CloudWatch Logs
      o Create/Select an IAM Role and Policy Name
      o Click Allow to continue
  
  Via CLI
  aws cloudtrail update-trail --name <trail_name> --cloudwatch-logs-log-group-
  arn <cloudtrail_log_group_arn> --cloudwatch-logs-role-arn <cloudtrail_cloudwatchLogs_role_arn>`,
  references: [
    `https://aws.amazon.com/cloudtrail/`,
    `CCE- 78916 - 4`,
    `CIS CSC v6.0 #6.6, #14.6`,
  ],
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
