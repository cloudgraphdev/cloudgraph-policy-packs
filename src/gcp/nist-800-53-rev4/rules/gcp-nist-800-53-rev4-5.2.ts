/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
/* eslint-disable @typescript-eslint/no-explicit-any */

const filterPatternRegex =
  /\s*protoPayload.methodName\s*=\s*"SetIamPolicy"\s*AND\s*protoPayload.serviceData.policyDelta.auditConfigDeltas:*\s*/

// GCP CIS 1.2.0 Rule equivalent 2.5
export default {
  id: 'gcp-nist-800-53-rev4-5.2',
  title:
    'GCP NIST 5.2 Logging metric filter and alert for audit configuration changes should be configured',
  description: `Google Cloud Platform (GCP) services write audit log entries to the Admin Activity and Data
  Access logs to help answer the questions of, "who did what, where, and when?" within GCP
  projects.

  Cloud audit logging records information includes the identity of the API caller, the time of
  the API call, the source IP address of the API caller, the request parameters, and the
  response elements returned by GCP services. Cloud audit logging provides a history of GCP
  API calls for an account, including API calls made via the console, SDKs, command-line
  tools, and other GCP services.`,
  audit: `**From Console:
  Ensure the prescribed log metric is present:**

  1. Go to *Logging/Logs-based Metrics* by visiting https://console.cloud.google.com/logs/metrics.
  2. In the *User-defined Metrics* section, ensure that at least one metric *<Log_Metric_Name>* is present with the filter text:

          protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*

  **Ensure that the prescribed alerting policy is present:**

  3. Go to Alerting by visiting https://console.cloud.google.com/monitoring/alerting.
  4. Under the Policies section, ensure that at least one alert policy exists for the log metric above. Clicking on the policy should show that it is configured with a condition. For example, *Violates when: Any logging.googleapis.com/user/<Log_Metric_Name> stream is above a threshold of 0 for greater than zero(0) seconds*, means that the alert will trigger for any new owner change. Verify that the chosen alerting thresholds make sense for the user's organization.
  5. Ensure that appropriate notifications channels have been set up.

  **From Command Line:
  Ensure that the prescribed log metric is present:**

  1. List the log metrics:

          gcloud beta logging metrics list --format json

  2. Ensure that the output contains at least one metric with the filter set to:

          protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*

  3. Note the value of the property *metricDescriptor.type* for the identified metric, in the format *logging.googleapis.com/user/<Log_Metric_Name>*.

  **Ensure that the prescribed alerting policy is present:**

  4. List the alerting policies:

          gcloud alpha monitoring policies list --format json

  5. Ensure that the output contains at least one alert policy where:

  - *conditions.conditionThreshold.filter* is set to *metric.type="logging.googleapis.com/user/<Log_Metric_Name>"*
  - AND *enabled* is set to *true*`,
  rationale: `Admin activity and data access logs produced by cloud audit logging enable security analysis, resource change tracking, and compliance auditing.

  Configuring the metric filter and alerts for audit configuration changes ensures the recommended state of audit configuration is maintained so that all activities in the project are audit-able at any point in time.`,
  remediation: `**From Console:
  Create the prescribed log metric:**

  1. Go to *Logging/Logs-based Metrics* by visiting https://console.cloud.google.com/logs/metrics and click "CREATE METRIC".
  2. Click the down arrow symbol on the *Filter Bar* at the rightmost corner and select *Convert to Advanced Filter*.
  3. Clear any text and add:

          protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*

  4. Click *Submit Filter*. Display logs appear based on the filter text entered by the user.
  5. In the *Metric Editor* menu on the right, fill out the name field. Set *Units* to *1* (default) and *Type* to *Counter*. This will ensure that the log metric counts the number of log entries matching the user's advanced logs query.
  6. Click *Create Metric*.

  **Create a prescribed Alert Policy:**

  1. Identify the new metric the user just created, under the section *User-defined Metrics* at https://console.cloud.google.com/logs/metrics.
  2. Click the 3-dot icon in the rightmost column for the new metric and select *Create alert from Metric*. A new page opens.
  3. Fill out the alert policy configuration and click *Save*. Choose the alerting threshold and configuration that makes sense for the organization. For example, a threshold of zero(0) for the most recent value will ensure that a notification is triggered for every owner change in the project:

          Set 'Aggregator' to 'Count'

          Set 'Configuration':

          - Condition: above

          - Threshold: 0

          - For: most recent value

      4. Configure the desired notifications channels in the section *Notifications*.
      5. Name the policy and click *Save*.

  **From Command Line:**
  Create a prescribed Log Metric:

  - Use the command: *gcloud beta logging metrics create*
  - Reference for command usage: https://cloud.google.com/sdk/gcloud/reference/beta/logging/metrics/create


  Create prescribed Alert Policy
  - Use the command: *gcloud alpha monitoring policies create*
  - Reference for command usage: https://cloud.google.com/sdk/gcloud/reference/alpha/monitoring/policies/create`,
  references: [
    'https://cloud.google.com/logging/docs/logs-based-metrics/',
    'https://cloud.google.com/monitoring/custom-metrics/',
    'https://cloud.google.com/monitoring/alerts/',
    'https://cloud.google.com/logging/docs/reference/tools/gcloud-logging',
    'https://cloud.google.com/logging/docs/audit/configure-data-access#getiampolicy-setiampolicy',
  ],
  gql: `{
    querygcpAlertPolicy {
      id
      __typename
      enabled {
        value
      }
      project {
        logMetrics {
          filter
        }
      }
    }
  }`,
  resource: 'querygcpAlertPolicy[*]',
  severity: 'medium',
  check: ({ resource }: any): boolean =>
    resource.enabled?.value === true &&
    resource.project?.every((p: any) =>
      p.logMetrics?.some(
        (lm: any) =>
          lm.metricDescriptor?.type ===
            `logging.googleapis.com/user/${lm.name}` &&
          filterPatternRegex.test(lm.filter)
      )
    ),
}
