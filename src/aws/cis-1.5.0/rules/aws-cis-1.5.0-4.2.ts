/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
/* eslint-disable @typescript-eslint/no-explicit-any */
// AWS CIS 1.2.0 Rule equivalent 3.2
export default {
  id: 'aws-cis-1.5.0-4.2',
  title:
    'AWS CIS 4.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA',
  description: `Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to
  CloudWatch Logs and establishing corresponding metric filters and alarms. It is
  recommended that a metric filter and alarm be established for console logins that are not
  protected by multi-factor authentication (MFA).`,
  audit: `Perform the following to ensure that there is at least one active multi-region CloudTrail
  with prescribed metric filters and alarms configured:

  1. Identify the log group name configured for use with active multi-region CloudTrail:

  - List all CloudTrails:

        aws cloudtrail describe-trails

  - Identify Multi region Cloudtrails: *Trails with "IsMultiRegionTrail" set to true*
  - From value associated with CloudWatchLogsLogGroupArn note *<cloudtrail_log_group_name>*

  Example: for CloudWatchLogsLogGroupArn that looks like _arn:aws:logs:<region>:<aws_account_number>:log-group:NewGroup:*, <cloudtrail_log_group_name>_ would be *NewGroup*

  - Ensure Identified Multi region CloudTrail is active

  *aws cloudtrail get-trail-status --name <Name_of_a_Multi-region_CloudTrail>* ensure *IsLogging* is set to *TRUE*

  - Ensure identified Multi-region Cloudtrail captures all Management Events

        aws cloudtrail get-event-selectors --trail-name <trailname_shown_in_describe-trails>

  Ensure there is at least one Event Selector for a Trail with *IncludeManagementEvents* set to *true* and *ReadWriteType* set to *All*

  2. Get a list of all associated metric filters for this *<cloudtrail_log_group_name>*:

    aws logs describe-metric-filters --log-group-name "<cloudtrail_log_group_name>"

  3. Ensure the output from the above command contains the following:

    "filterPattern": "{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }"

  4. Note the *<no_mfa_console_signin_metric>* value associated with the filterPattern found in step 3.
  5. Get a list of CloudWatch alarms and filter on the *<no_mfa_console_signin_metric>* captured in step 4.

     aws cloudwatch describe-alarms --query 'MetricAlarms[?MetricName== "<no_mfa_console_signin_metric>"]'

  6. Note the *AlarmActions* value - this will provide the SNS topic ARN value.
  7. Ensure there is at least one active subscriber to the SNS topic

    aws sns list-subscriptions-by-topic --topic-arn <sns_topic_arn>

  at least one subscription should have "SubscriptionArn" with valid aws ARN.

    Example of valid "SubscriptionArn": "arn:aws:sns:<region>:<aws_account_number>:<SnsTopicName>:<SubscriptionID>"`,
  rationale: 'Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA.',
  remediation: `Perform the following to setup the metric filter, alarm, SNS topic, and subscription:

  1. Create a metric filter based on the filter pattern provided which checks for AWS Management Console sign-in without MFA and the *<cloudtrail_log_group_name>* taken from audit step 1.

    aws logs put-metric-filter --log-group-name <cloudtrail_log_group_name> -- filter-name "<no_mfa_console_signin_metric>" --metric-transformations metricName= "<no_mfa_console_signin_metric>" ,metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }'

  **Note**: You can choose your own metricName and metricNamespace strings. Using the same metricNamespace for all Foundations Benchmark metrics will group them together.

  2. Create an SNS topic that the alarm will notify

    aws sns create-topic --name <sns_topic_name>

  **Note**: you can execute this command once and then re-use the same topic for all monitoring alarms.

  3. Create an SNS subscription to the topic created in step 2

    aws sns subscribe --topic-arn <sns_topic_arn> --protocol <protocol_for_sns> -- notification-endpoint <sns_subscription_endpoints>

  **Note**: you can execute this command once and then re-use the SNS subscription for all monitoring alarms.

  4. Create an alarm that is associated with the CloudWatch Logs Metric Filter created in step 1 and an SNS topic created in step 2

    aws cloudwatch put-metric-alarm --alarm-name "<no_mfa_console_signin_alarm>" --metric-name "<no_mfa_console_signin_metric>" --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold -- evaluation-periods 1 --namespace 'CISBenchmark' --alarm-actions <sns_topic_arn>`,
  references: [
    'http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/viewing_metrics_with_cloudwatch.html',
    'CCE-79187-1',
    'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html',
    'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html',
    'https://docs.aws.amazon.com/sns/latest/dg/SubscribeTopic.html',
  ],
  gql: `{
    queryawsAccount {
      id
       __typename
      cloudtrail {
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
    }
  }`,
  resource: 'queryawsAccount[*]',
  severity: 'medium',
  check: ({ resource }: any): any => {
    return resource.cloudtrail
      ?.filter(
        (cloudtrail: any) =>
          cloudtrail.cloudwatchLog?.length &&
          cloudtrail.isMultiRegionTrail === 'Yes' &&
          cloudtrail.status?.isLogging &&
          cloudtrail.eventSelectors?.some(
            (selector: any) =>
              selector.readWriteType === 'All' &&
              selector.includeManagementEvents
          )
      )
      ?.some((cloudtrail: any) => {
        const log = cloudtrail.cloudwatchLog[0]

        return log.metricFilters?.some((metricFilter: any) => {
          const metricTrasformation = metricFilter.metricTransformations?.find(
            (mt: any) =>
              log.cloudwatch?.find((cw: any) => cw.metric === mt.metricName)
          )

          if (!metricTrasformation) return false
          const metricCloudwatch = log.cloudwatch?.find(
            (cw: any) => cw.metric === metricTrasformation.metricName
          )

          return (
            metricCloudwatch?.sns?.some((sns: any) =>
              sns?.subscriptions?.some((sub: any) =>
                sub.arn.includes('arn:aws:')
              )
            ) &&
            /(\$.errorCode)\s*=\s*"ConsoleLogin"/.test(
              metricFilter.filterPattern
            ) &&
            /(\$.additionalEventData.MFAUsed)\s*!=\s*"Yes"/.test(
              metricFilter.filterPattern
            )
          )
        })
      })
  },
}
