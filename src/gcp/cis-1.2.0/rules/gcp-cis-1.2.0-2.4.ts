const filterPatternRegex =
  /\s*\(\s*protoPayload.serviceName\s*=\s*"cloudresourcemanager.googleapis.com"\s*\)\s*AND\s*\(\s*ProjectOwnership\s*OR\s*projectOwnerInvitee\s*\)\s*OR\s*\(\s*protoPayload.serviceData.policyDelta.bindingDeltas.action\s*=\s*"REMOVE"\s*AND\s*protoPayload.serviceData.policyDelta.bindingDeltas.role\s*=\s*"roles\/owner"\s*\)\s*OR\s*\(\s*protoPayload.serviceData.policyDelta.bindingDeltas.action\s*=\s*"ADD"\s*AND\s*protoPayload.serviceData.policyDelta.bindingDeltas.role\s*=\s*"roles\/owner"\s*\)\s*/

export default {
  id: 'gcp-cis-1.2.0-2.4',
  title:
    'GCP CIS 2.4 Ensure log metric filter and alerts exist for project ownership assignments/changes',
  description: `In order to prevent unnecessary project ownership assignments to users/service-accounts
  and further misuses of projects and resources, all roles/Owner assignments should be
  monitored.`,
  audit: `**From Console:
  Ensure that the prescribed log metric is present:**

  1. Go to *Logging/Log-based Metrics* by visiting https://console.cloud.google.com/logs/metrics.
  2. In the User-defined Metrics section, ensure that at least one metric *<Log_Metric_Name>* is present with filter text:

          (protoPayload.serviceName="cloudresourcemanager.googleapis.com")
          AND (ProjectOwnership OR projectOwnerInvitee)
          OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE"
          AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")
          OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"
          AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")

  **Ensure that the prescribed Alerting Policy is present:**

  3. Go to *Alerting* by visiting https://console.cloud.google.com/monitoring/alerting.
  4. Under the Policies section, ensure that at least one alert policy exists for the log metric above. Clicking on the policy should show that it is configured with a condition. For example, *Violates when: Any logging.googleapis.com/user/<LogMetric_Name> stream is above a threshold of zero(0) for greater than zero(0) seconds* means that the alert will trigger for any new owner change. Verify that the chosen alerting thresholds make sense for your organization.
  5. Ensure that the appropriate notifications channels have been set up.

  **From Command Line:
  Ensure that the prescribed log metric is present:**


  1. List the log metrics:

          gcloud beta logging metrics list --format json

  2. Ensure that the output contains at least one metric with filter set to:

          (protoPayload.serviceName="cloudresourcemanager.googleapis.com")
          AND (ProjectOwnership OR projectOwnerInvitee)
          OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE"
          AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")
          OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"
          AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")

  3. Note the value of the property *metricDescriptor.type* for the identified metric, in the format *logging.googleapis.com/user/<Log_Metric_Name>*.

  **Ensure that the prescribed alerting policy is present:**

  4. List the alerting policies:

          gcloud alpha monitoring policies list --format json

  5. Ensure that the output contains an least one alert policy where:


  - conditions.conditionThreshold.filter is set to *metric.type=\"logging.googleapis.com/user/<Log_Metric_Name>\"*
  - AND *enabled* is set to *true*`,
  rationale: `Project ownership has the highest level of privileges on a project. To avoid misuse of project resources, the project ownership assignment/change actions mentioned above should be monitored and alerted to concerned recipients.

  - Sending project ownership invites
  - Acceptance/Rejection of project ownership invite by user
  - Adding 'role\Owner' to a user/service-account
  - Removing a user/Service account from 'role\Owner'`,
  remediation: `**From Console:
  Create the prescribed log metric:**

  1. Go to *Logging/Logs-based Metrics* by visiting https://console.cloud.google.com/logs/metrics and click "CREATE METRIC".
  2. Click the down arrow symbol on the *Filter Bar* at the rightmost corner and select *Convert to Advanced Filter*.
  3. Clear any text and add:

          (protoPayload.serviceName="cloudresourcemanager.googleapis.com")
          AND (ProjectOwnership OR projectOwnerInvitee)
          OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE"
          AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")
          OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"
          AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")

  4. Click *Submit Filter*. The logs display based on the filter text entered by the user.
  5. In the *Metric Editor* menu on the right, fill out the name field. Set *Units* to **1** (default) and the *Type* to *Counter*. This ensures that the log metric counts the number of log entries matching the advanced logs query.
  6. Click *Create Metric*.

  **Create the display prescribed Alert Policy:**

  1. Identify the newly created metric under the section *User-defined Metrics* at https://console.cloud.google.com/logs/metrics.
  2. Click the 3-dot icon in the rightmost column for the desired metric and select *Create alert from Metric*. A new page opens.
  3. Fill out the alert policy configuration and click *Save*. Choose the alerting threshold and configuration that makes sense for the user's organization. For example, a threshold of zero(0) for the most recent value will ensure that a notification is triggered for every owner change in the project:

          Set 'Aggregator' to 'Count'

          Set 'Configuration':

          - Condition: above

          - Threshold: 0

          - For: most recent value

      4. Configure the desired notifications channels in the section *Notifications*.
      5. Name the policy and click *Save*.

  **From Command Line:**
  Create a prescribed Log Metric:


  - Use the command: gcloud beta logging metrics create
  - Reference for Command Usage: https://cloud.google.com/sdk/gcloud/reference/beta/logging/metrics/create

  Create prescribed Alert Policy

  - Use the command: gcloud alpha monitoring policies create
  - Reference for Command Usage: https://cloud.google.com/sdk/gcloud/reference/alpha/monitoring/policies/create`,
  references: [
    `https://cloud.google.com/logging/docs/logs-based-metrics/`,
    `https://cloud.google.com/monitoring/custom-metrics/`,
    `https://cloud.google.com/monitoring/alerts/`,
    `https://cloud.google.com/logging/docs/reference/tools/gcloud-logging`,
  ],
  gql: `{
    querygcpAlertPolicy {
      id
      __typename
      enabled {
        value
      }
      project {
        logMetric {
          filter
        }
      }
    }
  }`,
  resource: 'querygcpAlertPolicy[*]',
  severity: 'high',
  conditions: {
    and: [
      {
        path: '@.enabled.value',
        equal: true,
      },
      {
        path: '@.project',
        jq: '[.[].logMetric[] | select( "logging.googleapis.com/user/" + .name == .metricDescriptor.type)]',
        array_any: {
          path: '[*].filter',
          match: filterPatternRegex,
        },
      },
    ],
  },
}
