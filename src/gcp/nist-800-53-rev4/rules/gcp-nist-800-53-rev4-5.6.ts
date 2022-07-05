/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
/* eslint-disable @typescript-eslint/no-explicit-any */

const filterPatternRegex =
  /\s*resource.type\s*=\s*gce_network\s*AND\s*protoPayload.methodName\s*=\s*"beta.compute.networks.insert"\s*OR\s*protoPayload.methodName\s*=\s*"beta.compute.networks.patch"\s*OR\s*protoPayload.methodName\s*=\s*"v1.compute.networks.delete"\s*OR\s*protoPayload.methodName\s*=\s*"v1.compute.networks.removePeering"\s*OR\s*protoPayload.methodName\s*=\s*"v1.compute.networks.addPeering"\s*/

// GCP CIS 1.2.0 Rule equivalent 2.9
export default {
  id: 'gcp-nist-800-53-rev4-5.6',
  title:
    'GCP NIST 5.6 Logging metric filter and alert for network changes should be configured',
  description: `It is recommended that a metric filter and alarm be established for Virtual Private Cloud
  (VPC) network changes.`,
  audit: `**From Console:
  Ensure the prescribed log metric is present:**

  1. Go to *Logging/Logs-based Metrics* by visiting https://console.cloud.google.com/logs/metrics.
  2. In the *User-defined Metrics* section, ensure at least one metric *<Log_Metric_Name>* is present with filter text:

          resource.type=gce_network
          AND protoPayload.methodName="beta.compute.networks.insert"
          OR protoPayload.methodName="beta.compute.networks.patch"
          OR protoPayload.methodName="v1.compute.networks.delete"
          OR protoPayload.methodName="v1.compute.networks.removePeering"
          OR protoPayload.methodName="v1.compute.networks.addPeering"

  **Ensure the prescribed alerting policy is present:**

  3. Go to *Alerting* by visiting https://console.cloud.google.com/monitoring/alerting.


  4. Under the *Policies* section, ensure that at least one alert policy exists for the log metric above. Clicking on the policy should show that it is configured with a condition. For example, *Violates when: Any logging.googleapis.com/user/<Log_Metric_Name> stream is above a threshold of 0 for greater than 0 seconds* means that the alert will trigger for any new owner change. Verify that the chosen alerting thresholds make sense for the user's organization.
  5. Ensure that appropriate notification channels have been set up.

  **From Command Line:
  Ensure the log metric is present:**

  1. List the log metrics:

          gcloud beta logging metrics list --format json

  2. Ensure that the output contains at least one metric with filter set to:

          resource.type=gce_network
          AND protoPayload.methodName="beta.compute.networks.insert"
          OR protoPayload.methodName="beta.compute.networks.patch"
          OR protoPayload.methodName="v1.compute.networks.delete"
          OR protoPayload.methodName="v1.compute.networks.removePeering"
          OR protoPayload.methodName="v1.compute.networks.addPeering"

  3. Note the value of the property *metricDescriptor.type for* the identified metric, in
      the format l*ogging.googleapis.com/user/<Log_Metric_Name>*.

  **Ensure the prescribed alerting policy is present:**

  4. List the alerting policies:

          gcloud alpha monitoring policies list --format json

  5. Ensure that the output contains at least one alert policy where:

  - *conditions.conditionThreshold.filter* is set to *metric.type=\\"logging.googleapis.com/user/<Log Metric Name>\\"*
  - AND *enabled* is set to *true*`,
  rationale: `It is possible to have more than one VPC within a project. In addition, it is also possible to create a peer connection between two VPCs enabling network traffic to route between VPCs.

  Monitoring changes to a VPC will help ensure VPC traffic flow is not getting impacted.`,
  remediation: `**From Console:
  Create the prescribed log metric:**

  1. Go to *Logging/Logs-based Metrics* by visiting https://console.cloud.google.com/logs/metrics and click "CREATE METRIC".
  2. Click the down arrow symbol on *Filter Bar* at the rightmost corner and select *Convert to Advanced Filter*.

  3. Clear any text and add:

          resource.type=gce_network
          AND protoPayload.methodName="beta.compute.networks.insert"
          OR protoPayload.methodName="beta.compute.networks.patch"
          OR protoPayload.methodName="v1.compute.networks.delete"
          OR protoPayload.methodName="v1.compute.networks.removePeering"
          OR protoPayload.methodName="v1.compute.networks.addPeering"

  4. Click *Submit Filter*. Display logs appear based on the filter text entered by the user.
  5. In the *Metric Editor* menu on the right, fill out the name field. Set *Units* to *1*
      (default) and *Type* to *Counter*. This ensures that the log metric counts the number of
      log entries matching the user's advanced logs query.
  6. Click *Create Metric*.

  **Create the prescribed alert policy:**

  1. Identify the newly created metric under the section *User-defined Metrics* at https://console.cloud.google.com/logs/metrics.
  2. Click the 3-dot icon in the rightmost column for the new metric and select *Create alert from Metric*. A new page appears.
  3. Fill out the alert policy configuration and click *Save*. Choose the alerting threshold and configuration that makes sense for the user's organization. For example, a threshold of 0 for the most recent value will ensure that a notification is triggered for every owner change in the project:

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

  Create the prescribed alert policy:

  - Use the command: *gcloud alpha monitoring policies create*
  - Reference for command usage: https://cloud.google.com/sdk/gcloud/reference/alpha/monitoring/policies/create`,
  references: [
    'https://cloud.google.com/logging/docs/logs-based-metrics/',
    'https://cloud.google.com/monitoring/custom-metrics/',
    'https://cloud.google.com/monitoring/alerts/',
    'https://cloud.google.com/logging/docs/reference/tools/gcloud-logging',
    'https://cloud.google.com/vpc/docs/overview',
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
