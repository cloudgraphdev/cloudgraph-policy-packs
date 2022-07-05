/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
/* eslint-disable @typescript-eslint/no-explicit-any */
// AWS CIS-1.3.0 Rule equivalent 4.15
const filterPatternRegex =
/\(\$\.eventSource\s*=\s*organizations\.amazonaws\.com\)\s*&&\s*\(\(\$\.eventName\s*=\s*"AcceptHandshake"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"AttachPolicy"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"CreateAccount"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"CreateOrganizationalUnit"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"CreatePolicy"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"DeclineHandshake"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"DeleteOrganization"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"DeleteOrganizationalUnit"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"DeletePolicy"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"DetachPolicy"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"DisablePolicyType"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"EnablePolicyType"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"InviteAccountToOrganization"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"LeaveOrganization"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"MoveAccount"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"RemoveAccountFromOrganization"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"UpdatePolicy"\)\s*\|\|\s*\(\$\.eventName\s*=\s*"UpdateOrganizationalUnit"\)\)/

export default {
  id: 'aws-nist-800-53-rev4-7.2',
  title: 'AWS NIST 7.2 CloudWatch log metric filter and alarm for AWS Organizations changes should be configured for the master account',
  
  description: 'Monitoring AWS Organizations changes can help you prevent any unwanted, accidental or intentional modifications that may lead to unauthorized access or other security breaches. This monitoring technique helps you to ensure that any unexpected changes performed within your AWS Organizations can be investigated and any unwanted changes can be rolled back.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**Console Remediation Steps**
  
  Create the Metric Filter:
  
  - Navigate to CloudWatch.
  - In the left navigation, click Logs.
  - Select the log group that you created for CloudTrail log events.
  - Choose Actions > Create Metric Filter.
  - On the Define Pattern screen, enter the following:
  
          { ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy") || ($.eventName = "UpdateOrganizationalUnit")) }
  
  - Select Next.
  - Enter a filter name.
  - Enter a metric name.
  - For Metric Value, type 1.
  - Select Next.
  - Select Create Metric Filter.
  
  Create an Alarm:
  
  - On the Metric Filters tab of the same log group, check the box for the filter you just created and click Create Alarm.
  - On the Create Alarm page, provide the following values:
  - Under Statistic, select Sum.
  - Under Period, select 5 minutes.
  - Under Threshold type, select Static.
  - Under “Whenever <filter name> is…” select Greater/Equal.
  - Under “than…” enter 1.
  - Set Datapoints to alarm to 1 out of 1.
  - Select Next.
  - On the Configure Actions page, provide the following values:
  - Under Alarm state trigger, select In alarm.
  - Under Select an SNS topic, click Select an existing SNS topic.
  - Under Send a notification to… select the desired topic.
  - Select next.
  - Enter an alarm name and description.
  - Click Create Alarm.
  
  **CLI Remediation Steps**
  
  To enable CloudWatch log metric filter and alarm for AWS Organizations changes for the master account:
  
  Create a metric filter:
  
      aws logs put-metric-filter --log-group-name <cloudtrail_log_group_name> --filter-name '<organizations_changes>' --metric-transformations metricName= '<organizations_changes>',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy") || ($.eventName = "UpdateOrganizationalUnit")) }'
  
  Create an SNS topic that the alarm will notify:
  
      aws sns create-topic --name <sns_topic_name>
  
  Create an SNS subscription to the topic created in step 2:
  
      aws sns subscribe --topic-arn <sns_topic_arn> --protocol <protocol_for_sns> --notification-endpoint <sns_subscription_endpoints>
  
  Create an alarm that is associated with the CloudWatch Logs Metric Filter created in step 1 and an SNS topic created in step 2:',
  
      aws cloudwatch put-metric-alarm --alarm-name '<organizations_changes>' --metric-name '<organizations_changes>' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark' --alarm-actions <sns_topic_arn>`,
  
  references: [
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html',
      'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_security_incident-response.html',
      'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html',
      'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_tutorials_cwe.html',
      'https://docs.aws.amazon.com/cli/latest/reference/logs/put-metric-filter.html',
      'https://docs.aws.amazon.com/cli/latest/reference/cloudwatch/put-metric-alarm.html',
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
      .filter(
        (cloudtrail: any) =>
          cloudtrail.cloudwatchLog?.length &&
          cloudtrail.isMultiRegionTrail === 'Yes' &&
          cloudtrail.status.isLogging &&
          cloudtrail.eventSelectors.some(
            (selector: any) =>
              selector.readWriteType === 'All' &&
              selector.includeManagementEvents
          )
      )
      .some((cloudtrail: any) => {
        const log = cloudtrail.cloudwatchLog[0]

        return log.metricFilters.some((metricFilter: any) => {
          const metricTrasformation = metricFilter.metricTransformations.find(
            (mt: any) =>
              log.cloudwatch?.find((cw: any) => cw.metric === mt.metricName)
          )

          if (!metricTrasformation) return false
          const metricCloudwatch = log.cloudwatch.find(
            (cw: any) => cw.metric === metricTrasformation.metricName
          )

          return (
            metricCloudwatch?.sns?.some((sns: any) =>
              sns?.subscriptions?.some((sub: any) =>
                sub.arn.includes('arn:aws:')
              )
            ) &&
            filterPatternRegex.test(metricFilter.filterPattern)
          )
        })
      })
  },
}
