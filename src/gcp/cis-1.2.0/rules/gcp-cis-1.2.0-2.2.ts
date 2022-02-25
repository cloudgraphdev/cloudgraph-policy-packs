export default {
  id: 'gcp-cis-1.2.0-2.2',
  title: 'GCP CIS 2.2 Ensure that sinks are configured for all log entries',
  description: `It is recommended to create a sink that will export copies of all the log entries. This can
  help aggregate logs from multiple projects and export them to a Security Information and
  Event Management (SIEM).`,
  audit: `**From Console:**

  1. Go to *Logging/Exports* by visiting https://console.cloud.google.com/logs/exports.
  2. For every sink, click the 3-dot button for Menu options and select *View Filter*.
  3. Ensure there is at least one sink with an *empty* sink filter.
  4. Additionally, ensure that the resource configured as *Destination* exists.

  **From Command Line:**

  1. Ensure that a sink with an *empty filter* exists. List the sinks for the project, folder or organization. If sinks are configured at a folder or organization level, they do not need to be configured for each project:

          gcloud logging sinks list --folder=FOLDER_ID | --organization=ORGANIZATION_ID | --project=PROJECT_ID

  The output should list at least one sink with an *empty filter*.

  2. Additionally, ensure that the resource configured as *Destination* exists.

  See https://cloud.google.com/sdk/gcloud/reference/beta/logging/sinks/list for more information.`,
  rationale: `Log entries are held in Cloud Logging. To aggregate logs, export them to a SIEM. To keep them longer, it is recommended to set up a log sink. Exporting involves writing a filter that selects the log entries to export, and choosing a destination in Cloud Storage, BigQuery, or Cloud Pub/Sub. The filter and destination are held in an object called a sink. To ensure all log entries are exported to sinks, ensure that there is no filter configured for a sink. Sinks can be created in projects, organizations, folders, and billing accounts.`,
  remediation: `**From Console:**

  1. Go to *Logging/Logs* by visiting https://console.cloud.google.com/logs/viewer.
  2. Click the down arrow symbol on *Filter Bar* at the rightmost corner and select
      *Convert to Advanced Filter*.
  3. This step converts *Filter Bar* to *Advanced Filter Bar*.
  4. Clear any text from the *Advanced Filter* field. This ensures that the *log-filter* is
      set to empty and captures all the logs.
  5. Click *Submit Filter* and the result should display all logs.
  6. Click *Create Sink*, which opens a menu on the right.
  7. Fill out the fields and click *Create Sink*.

  For more information, see https://cloud.google.com/logging/docs/export/configure_export_v2#dest-create.

  **From Command Line:**
  To create a sink to export all log entries in a Google Cloud Storage bucket:

      gcloud logging sinks create <sink-name> storage.googleapis.com/DESTINATION_BUCKET_NAME

  Sinks can be created for a folder or organization, which will include all projects.

      gcloud logging sinks create <sink-name> storage.googleapis.com/DESTINATION_BUCKET_NAME --include-children -- folder=FOLDER_ID | --organization=ORGANIZATION_ID

  **Note:**

  1. A sink created by the command-line above will export logs in storage buckets. However, sinks can be configured to export logs into BigQuery, or Cloud Pub/Sub, or *Custom Destination*.
  2. While creating a sink, the sink option *--log-filter* is not used to ensure the sink exports all log entries.
  3. A sink can be created at a folder or organization level that collects the logs of all the projects underneath bypassing the option *--include-children* in the cloud command.`,
  references: [
    `https://cloud.google.com/logging/docs/reference/tools/gcloud-logging`,
    `https://cloud.google.com/logging/quotas`,
    `https://cloud.google.com/logging/docs/export/`,
    `https://cloud.google.com/logging/docs/export/using_exported_logs`,
    `https://cloud.google.com/logging/docs/export/configure_export_v2`,
    `https://cloud.google.com/logging/docs/export/aggregated_exports`,
    `https://cloud.google.com/sdk/gcloud/reference/beta/logging/sinks/list`,
  ],
  gql: `{
    querygcpProject {
      id
      __typename
      logSinks {
        filter
      }
    }
  }`,
  resource: 'querygcpProject[*]',
  severity: 'high',
  conditions: {
    path: '@.logSinks',
    array_any: {
      path: '[*].filter',
      equal: '',
    },
  },
}
