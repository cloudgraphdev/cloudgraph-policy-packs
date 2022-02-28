// AWS CIS 1.2.0 Rule equivalent 3.3
export default {
  id: 'aws-pci-dss-3.2.1-cloudwatch-check-1',
  title:
    'Cloudwatch Check 1: A log metric filter and alarm should exist for usage of the "root" user',
  description: `This control checks for the CloudWatch metric filters using the following pattern:


  \` \{ \$.userIdentity.type = "Root" \&\& \$.userIdentity.invokedBy NOT EXISTS \&\& \$.eventType \!\= "AwsServiceEvent" \} \`

   It checks the following:

   - The log group name is configured for use with active multi-Region CloudTrail.
   - There is at least one Event Selector for a Trail with   \`IncludeManagementEvents\` set to true and \`ReadWriteType\` set to \`All\`.
   - There is at least one active subscriber to an Amazon SNS topic associated with the alarm.`,
  rationale: `This control is related to the following PCI DSS requirements:

  **PCI DSS 7.2.1: Establish an access control system(s) for systems components that restricts access based on a user’s need to know, and is set to "deny all" unless specifically allowed. This access control system(s) must include the following: Coverage of all system components.**

  The root user is the most privileged user in an AWS account and has unrestricted access to all resources in the AWS account.

  You should set up log metric filters and alarms in the event that AWS account root user credentials are used.

  You should also ensure that CloudTrail is enabled to keep an audit trail of actions taken by any individual with root or administrative privileges (see [[PCI.CloudTrail.2] CloudTrail should be enabled](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-cloudtrail-2)). Root user identification would be found in the userIdentity section of the CloudTrail log.
  `,
  remediation: `The steps to remediate this issue include setting up an Amazon SNS topic, a metric filter, and an alarm for the metric filter.

  These are the same steps to remediate findings for [3.3 – Ensure a log metric filter and alarm exist for usage of "root" account](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.3).

  **To create an Amazon SNS topic**

  1. Open the Amazon SNS console at https://console.aws.amazon.com/sns/v3/home.
  2. Create an Amazon SNS topic that receives all CIS alarms.

     Create at least one subscriber to the topic.

     For more information about creating Amazon SNS topics, see the [Amazon Simple Notification Service Developer Guide](https://docs.aws.amazon.com/sns/latest/dg/sns-getting-started.html#CreateTopic).

  3. Set up an active CloudTrail trail that applies to all Regions.

     To do this, follow the remediation steps in [2.1 – Ensure CloudTrail is enabled in all Regions](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.1).

     Make a note of the associated log group name.

  **To create a metric filter and alarm**

  1. Open the CloudWatch console at https://console.aws.amazon.com/cloudwatch/.
  2. Choose **Logs**, then choose **Log groups**.
  3. Choose the log group where CloudTrail is logging.
  4. On the log group details page, choose **Metric filters**.
  5. Choose **Create metric filter**.
  6. Copy the following pattern and then paste it into **Filter pattern**.


     \` \{ \$.userIdentity.type = "Root" \&\& \$.userIdentity.invokedBy NOT EXISTS \&\& \$.eventType \!\= "AwsServiceEvent" \} \`


  7. Choose **Next**.
  8. Enter the name of the new filter. For example, \`RootAccountUsage\`.
  9. Confirm that the value for **Metric namespace** is \`LogMetrics\`.
  This ensures that all CIS Benchmark metrics are grouped together.
  10. In **Metric name**, enter the name of the metric.
  11. In **Metric value**, enter \`1\`, and then choose **Next**.
  12. Choose **Create metric filter**.
  13. Next, set up the notification. Select the metric filter you just created, then choose **Create alarm**.
  14. Enter the threshold for the alarm (for example, \`1\`), then choose **Next**.
  15. Under **Select an SNS topic**, for **Send notification to**, choose an email list, then choose **Next**.
  16. Enter a **Name** and **Description** for the alarm, such as 17. \`RootAccountUsageAlarm\`, then choose **Next**.
  17. Choose **Create Alarm**.`,
  references: [
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html',
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-cloudtrail-2',
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.3',
    'https://docs.aws.amazon.com/sns/latest/dg/sns-getting-started.html#CreateTopic',
    'https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-2.1'
  ],
  gql: `{
    queryawsCloudtrail(filter: { isMultiRegionTrail: { eq: "Yes" } }) {
      id
      arn
      accountId
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
  severity: 'high',
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
              match:
                // eslint-disable-next-line max-len
                /(\$.userIdentity.type)\s*=\s*"Root"*\s&&\s*(\$.userIdentity.invokedBy)\s*NOT\s*EXISTS\s*&&\s*(\$.eventType)\s*!=\s*"AwsServiceEvent"/,
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
