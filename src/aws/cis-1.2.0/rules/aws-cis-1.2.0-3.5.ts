export default {
  id: 'aws-cis-1.2.0-3.5',
  description:
    'AWS CIS 3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)',
  audit: `Perform the following to ensure that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured:

  1. Identify the log group name configured for use with active multi-region CloudTrail:
  
  - List all CloudTrails: *aws cloudtrail describe-trails*
  
  - Identify Multi region Cloudtrails: *Trails with "IsMultiRegionTrail" set to true*
  - From value associated with CloudWatchLogsLogGroupArn note *<cloudtrail_log_group_name>*
  
  Example: for CloudWatchLogsLogGroupArn that looks like *arn:aws:logs:<region>:<aws_account_number>:log-group:NewGroup:\*, <cloudtrail_log_group_name>* would be *NewGroup*
  
  - Ensure Identified Multi region CloudTrail is active
  
  *aws cloudtrail get-trail-status --name <Name_of_a_Multi-region_CloudTrail>* ensure *IsLogging* is set to *TRUE*
  
  - Ensure identified Multi-region Cloudtrail captures all Management Events
  
  *aws cloudtrail get-event-selectors --trail-name <trailname_shown_in_describe-trails>*

  Ensure there is at least one Event Selector for a Trail with *IncludeManagementEvents* set to *true* and *ReadWriteType* set to *All*
  
  2. Get a list of all associated metric filters for this *<cloudtrail_log_group_name>*:
  
    aws logs describe-metric-filters --log-group-name "<cloudtrail_log_group_name>"
  
  3. Ensure the output from the above command contains the following:
  
    "filterPattern": "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
  
  4. Note the *<cloudtrail_cfg_changes_metric>* value associated with the *filterPattern* found in step 3.
  5. Get a list of CloudWatch alarms and filter on the *<cloudtrail_cfg_changes_metric>* captured in step 4.
  
    aws cloudwatch describe-alarms --query 'MetricAlarms[?MetricName== "<cloudtrail_cfg_changes_metric>"]'  

  6. Note the *AlarmActions* value - this will provide the SNS topic ARN value.
  7. Ensure there is at least one active subscriber to the SNS topic
  
    aws sns list-subscriptions-by-topic --topic-arn <sns_topic_arn>
  
  at least one subscription should have "SubscriptionArn" with valid aws ARN.
  
    Example of valid "SubscriptionArn": "arn:aws:sns:<region>:<aws_account_number>:<SnsTopicName>:<SubscriptionID>"`,
  rationale: `Monitoring changes to CloudTrail's configuration will help ensure sustained visibility to activities performed in the AWS account.`,
  remediation: `Perform the following to setup the metric filter, alarm, SNS topic, and subscription:

  1. Create a metric filter based on filter pattern provided which checks for cloudtrail configuration changes and the *<cloudtrail_log_group_name>* taken from audit step 1.
  
    aws logs put-metric-filter --log-group-name <cloudtrail_log_group_name> -- filter-name "<cloudtrail_cfg_changes_metric>" --metric-transformations metricName= "<cloudtrail_cfg_changes_metric>" ,metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }'
  
  **Note**: You can choose your own metricName and metricNamespace strings. Using the same metricNamespace for all Foundations Benchmark metrics will group them together.
  
  2. Create an SNS topic that the alarm will notify
  
    aws sns create-topic --name <sns_topic_name>
  
  **Note**: you can execute this command once and then re-use the same topic for all monitoring alarms.
  
  3. Create an SNS subscription to the topic created in step 2
  
    aws sns subscribe --topic-arn <sns_topic_arn> --protocol <protocol_for_sns> -- notification-endpoint <sns_subscription_endpoints>
  
  **Note** : you can execute this command once and then re-use the SNS subscription for all monitoring alarms.
  
  4. Create an alarm that is associated with the CloudWatch Logs Metric Filter created in step 1 and an SNS topic created in step 2
  
    aws cloudwatch put-metric-alarm --alarm-name "<cloudtrail_cfg_changes_alarm>" --metric-name "<cloudtrail_cfg_changes_metric>" --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 -- namespace 'CISBenchmark' --alarm-actions <sns_topic_arn>`,
  references: [
    `CCE- 79190 - 5`,
    `https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html`,
    `https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html`,
    `https://docs.aws.amazon.com/sns/latest/dg/SubscribeTopic.html`,
  ],
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
              match: /(\$.eventName)\s*=\s*CreateTrail/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*UpdateTrail/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*DeleteTrail/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*StartLogging/,
            },
            {
              path: '[*].filterPattern',
              match: /(\$.eventName)\s*=\s*StopLogging/,
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
