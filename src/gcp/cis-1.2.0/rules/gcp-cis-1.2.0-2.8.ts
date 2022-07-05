/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
/* eslint-disable @typescript-eslint/no-explicit-any */

const filterPatternRegex =
  /\s*resource.type\s*=\s*"gce_route"\s*AND\s*protoPayload.methodName\s*=\s*"beta.compute.routes.patch"\s*OR\s*protoPayload.methodName\s*=\s*"beta.compute.routes.insert"\s*/

export default {
  id: 'gcp-cis-1.2.0-2.8',
  title:
    'GCP CIS 2.8 Ensure that the log metric filter and alerts exist for VPC network route changes',
  description: `It is recommended that a metric filter and alarm be established for Virtual Private Cloud
  (VPC) network route changes.`,
  audit: `**From Console:
  Ensure that the prescribed Log metric is present:**

  1. Go to *Logging/Logs-based Metrics* by visiting https://console.cloud.google.com/logs/metrics.
  2. In the *User-defined Metrics* section, ensure that at least one metric *<Log_Metric_Name>* is present with the filter text:

           resource.type="gce_route" AND protoPayload.methodName="beta.compute.routes.patch" OR protoPayload.methodName="beta.compute.routes.insert"

  **Ensure the prescribed alerting policy is present:**

  3. Go to *Alerting* by visiting: https://console.cloud.google.com/monitoring/alerting.
  4. Under the *Policies* section, ensure that at least one alert policy exists for the log metric above. Clicking on the policy should show that it is configured with a condition. For example, *Violates when: Any logging.googleapis.com/user/<Log_Metric_Name> stream is above a threshold of 0 for greater than zero(0) seconds* means that the alert will trigger for any new owner change. Verify that the chosen alert thresholds make sense for the user's organization.
  5. Ensure that the appropriate notification channels have been set up.

  **From Command Line:
  Ensure the prescribed log metric is present:**

  1. List the log metrics:

          gcloud beta logging metrics list --format json

  2. Ensure that the output contains at least one metric with the filter set to:

           resource.type="gce_route" AND protoPayload.methodName="beta.compute.routes.patch" OR protoPayload.methodName="beta.compute.routes.insert"

  3. Note the value of the property *metricDescriptor.type* for the identified metric, in the format *logging.googleapis.com/user/<Log Metric Name>*.

  **Ensure that the prescribed alerting policy is present:**

  4. List the alerting policies:

          gcloud alpha monitoring policies list --format json

  5. Ensure that the output contains an least one alert policy where:

  - *conditions.conditionThreshold.filter* is set to *metric.type="logging.googleapis.com/user/<Log_Metric_Name>"*
  - AND *enabled* is set to *true*`,
  rationale: `Google Cloud Platform (GCP) routes define the paths network traffic takes from a VM instance to another destination. The other destination can be inside the organization VPC network (such as another VM) or outside of it. Every route consists of a destination and a next hop. Traffic whose destination IP is within the destination range is sent to the next hop for delivery.

  Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path.`,
  remediation: `**From Console:
  Create the prescribed Log Metric:**

  1. Go to *Logging/Logs-based Metrics* by visiting https://console.cloud.google.com/logs/metrics and click "CREATE METRIC".
  2. Click the down arrow symbol on the *Filter Bar* at the rightmost corner and select *Convert to Advanced Filter*

  3. Clear any text and add:

          resource.type="gce_route" AND protoPayload.methodName="beta.compute.routes.patch" OR protoPayload.methodName="beta.compute.routes.insert"

  4. Click *Submit Filter*. Display logs appear based on the filter text entered by the user.
  5. In the *Metric Editor* menu on the right, fill out the name field. Set *Units* to *1* (default) and *Type* to *Counter*. This ensures that the log metric counts the number of log entries matching the user's advanced logs query.
  6. Click *Create Metric*.

  **Create the prescribed alert policy:**

  1. Identify the newly created metric under the section *User-defined Metrics* at https://console.cloud.google.com/logs/metrics.
  2. Click the 3-dot icon in the rightmost column for the new metric and select *Create alert from Metric*. A new page displays.
  3. Fill out the alert policy configuration and click *Save*. Choose the alerting threshold
      and configuration that makes sense for the user's organization. For example, a
      threshold of zero(0) for the most recent value ensures that a notification is triggered
      for every owner change in the project:

          Set "Aggregator" to "Count"

          Set "Configuration":

          - Condition: above

          - Threshold: 0

          - For: most recent value

  4. Configure the desired notification channels in the section *Notifications*.
  5. Name the policy and click *Save*.

  **From Command Line:**
  Create the prescribed Log Metric:


  - Use the command: *gcloud beta logging metrics create*
  - Reference for command usage: https://cloud.google.com/sdk/gcloud/reference/beta/logging/metrics/create

  Create the prescribed the alert policy:
  - Use the command: *gcloud alpha monitoring policies create*
  - Reference for command usage: https://cloud.google.com/sdk/gcloud/reference/alpha/monitoring/policies/create
  `,
  references: [
    'https://cloud.google.com/logging/docs/logs-based-metrics/',
    'https://cloud.google.com/monitoring/custom-metrics/',
    'https://cloud.google.com/monitoring/alerts/',
    'https://cloud.google.com/logging/docs/reference/tools/gcloud-logging',
    'https://cloud.google.com/storage/docs/access-control/iam',
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
