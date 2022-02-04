export default {
  id: 'aws-cis-1.2.0-3.4',
  title:
    'AWS CIS 3.4 Ensure a log metric filter and alarm exist for IAM policy changes (Score)',
  description: `Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to
  CloudWatch Logs and establishing corresponding metric filters and alarms. It is
  recommended that a metric filter and alarm be established changes made to Identity and
  Access Management (IAM) policies.`,
  audit: `Perform the following to ensure that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured:

  1. Identify the log group name configured for use with active multi-region CloudTrail:

  - List all CloudTrails:

        aws cloudtrail describe-trails

  - Identify Multi region Cloudtrails: *Trails with "IsMultiRegionTrail" set to true*
  - From value associated with CloudWatchLogsLogGroupArn note *<cloudtrail_log_group_name>*

  Example: for CloudWatchLogsLogGroupArn that looks like
  *arn:aws:logs:<region>:<aws_account_number>:log-group:NewGroup:\*, <cloudtrail_log_group_name>* would be *NewGroup*

  - Ensure Identified Multi region CloudTrail is active

  *aws cloudtrail get-trail-status --name <Name_of_a_Multi-region_CloudTrail>* ensure *IsLogging* is set to *TRUE*

  - Ensure identified Multi-region Cloudtrail captures all Management Events

  *aws cloudtrail get-event-selectors --trail-name <trailname_shown_in_describe-trails>*

  Ensure there is at least one Event Selector for a Trail with *IncludeManagementEvents* set to *true* and *ReadWriteType* set to *All*

  2. Get a list of all associated metric filters for this* <cloudtrail_log_group_name>*:

    aws logs describe-metric-filters --log-group-name "<cloudtrail_log_group_name>"

  3. Ensure the output from the above command contains the following:

    "filterPattern": "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventNa me=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolic y)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=Del etePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersi on)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.event Name=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGr oupPolicy)||($.eventName=DetachGroupPolicy)}"

  4. Note the *<iam_changes_metric>* value associated with the *filterPattern* found in step 3.
  5. Get a list of CloudWatch alarms and filter on the *<iam_changes_metric>* captured in step 4.

    aws cloudwatch describe-alarms --query 'MetricAlarms[?MetricName== "<iam_changes_metric>"]'

  6. Note the *AlarmActions* value - this will provide the SNS topic ARN value.
  7. Ensure there is at least one active subscriber to the SNS topic

    aws sns list-subscriptions-by-topic --topic-arn <sns_topic_arn>

  at least one subscription should have "SubscriptionArn" with valid aws ARN.

    Example of valid "SubscriptionArn": "arn:aws:sns:<region>:<aws_account_number>:<SnsTopicName>:<SubscriptionID>"`,
  rationale: `Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact.`,
  remediation: `Perform the following to setup the metric filter, alarm, SNS topic, and subscription:

  1. Create a metric filter based on the filter pattern provided which checks for IAM policy changes and the *<cloudtrail_log_group_name>* taken from audit step 1.

    aws logs put-metric-filter --log-group-name "<cloudtrail_log_group_name>" -- filter-name "<iam_changes_metric>" --metric-transformations metricName= "<iam_changes_metric>" ,metricNamespace='CISBenchmark',metricValue=1 -- filter-pattern '{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventNa me=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolic y)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=Del etePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersi on)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.event Name=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGr oupPolicy)||($.eventName=DetachGroupPolicy)}'

  **Note**: You can choose your own metricName and metricNamespace strings. Using the same metricNamespace for all Foundations Benchmark metrics will group them together.

  2. Create an SNS topic that the alarm will notify

    aws sns create-topic --name <sns_topic_name>

  **Note** : you can execute this command once and then re-use the same topic for all monitoring alarms.

  3. Create an SNS subscription to the topic created in step 2

    aws sns subscribe --topic-arn <sns_topic_arn> --protocol <protocol_for_sns> --notification-endpoint <sns_subscription_endpoints>

  **Note** : you can execute this command once and then re-use the SNS subscription for all monitoring alarms.

  4. Create an alarm that is associated with the CloudWatch Logs Metric Filter created in step 1 and an SNS topic created in step 2

    aws cloudwatch put-metric-alarm --alarm-name "<iam_changes_alarm>" -- metric-name "<iam_changes_metric>" --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark' --alarm-actions <sns_topic_arn>`,
  references: [
    `CCE- 79189 - 7`,
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
