export default {
  id: 'aws-pci-dss-3.2.1-cloudtrail-check-4',
  title:
    'CloudTrail Check 4: CloudTrail trails should be integrated with CloudWatch Logs',
  description: `This control checks whether CloudTrail trails are configured to send logs to CloudWatch Logs.

  It does not check for user permissions to alter logs or log groups. You should create specific CloudWatch rules to alert when CloudTrail logs are altered.

  This control also does not check for any additional audit log sources other than CloudTrail being sent to a CloudWatch Logs group.`,
  rationale: `**PCI DSS 10.5.3: Promptly back up audit trail files to a centralized log server or media that is difficult to alter.**
  CloudTrail uses Amazon S3 for log file storage and delivery, so log files are stored permanently.

  CloudWatch Logs is a native way to promptly back up audit trail files.`,
  remediation: `**To ensure that CloudTrail trails are integrated with CloudWatch Logs**

  1. Open the CloudTrail console at https://console.aws.amazon.com/cloudtrail/.

  2. Choose **Trails**.

  3. Choose a trail that there is no value for in the **CloudWatch Logs Log group** column.

  4. Scroll down to the **CloudWatch Logs** section and then choose **Edit**.

  5. For **Log group** field, do one of the following:

     - To use the default log group, keep the name as is.

     - To use an existing log group, choose **Existing** and then enter the name of the log group to use.

     - To create a new log group, choose **New** and then enter a name for the log group to create.

  6. Choose **Continue**.

  7. For **IAM role**, do one of the following:

     - To use an existing role, choose **Existing** and then choose the role from the drop-down list.

     - To create a new role, choose **New** and then enter a name for the role to create.

     - The new role is assigned a policy that grants the necessary permissions.

  To view the permissions granted to the role, expand the **Policy document**.

  8. Choose Save changes.
     For more information about configuring CloudWatch Logs monitoring with the console, see the [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html#send-cloudtrail-events-to-cloudwatch-logs-console).`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html#send-cloudtrail-events-to-cloudwatch-logs-console',
  ],
  gql: `{
    queryawsCloudtrail {
      id
      arn
      accountId
      __typename
      cloudWatchLogsRoleArn
      status {
        latestCloudWatchLogsDeliveryTime
      }
    }
  }`,
  resource: 'queryawsCloudtrail[*]',
  severity: 'low',
  conditions: {
    and: [
      {
        path: '@.cloudWatchLogsRoleArn',
        isEmpty: false,
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
