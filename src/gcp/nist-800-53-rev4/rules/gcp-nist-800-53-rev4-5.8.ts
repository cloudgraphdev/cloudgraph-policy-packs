// GCP CIS 1.2.0 Rule equivalent 2.3
export default {
  id: 'gcp-nist-800-53-rev4-5.8',
  title:
    'GCP NIST 5.8 Logging storage bucket retention policies and Bucket Lock should be configured',
  description: `Enabling retention policies on log buckets will protect logs stored in cloud storage buckets
  from being overwritten or accidentally deleted. It is recommended to set up retention
  policies and configure Bucket Lock on all storage buckets that are used as log sinks.`,
  audit: `**From Console:**

  1. Open the Cloud Storage browser in the Google Cloud Console by visiting https://console.cloud.google.com/storage/browser.
  2. In the Column display options menu, make sure *Retention policy* is checked.
  3. In the list of buckets, the retention period of each bucket is found in the *Retention policy* column. If the retention policy is locked, an image of a lock appears directly to the left of the retention period.


  **From Command Line:**

  1. To list all sinks destined to storage buckets:

          gcloud logging sinks list --folder=FOLDER_ID | --organization=ORGANIZATION_ID | --project=PROJECT_ID

  2. For every storage bucket listed above, verify that retention policies and Bucket Lock
      are enabled:

          gsutil retention get gs://BUCKET_NAME

  For more information, see https://cloud.google.com/storage/docs/using-bucket-lock#view-policy.`,
  rationale: `Logs can be exported by creating one or more sinks that include a log filter and a destination. As Cloud Logging receives new log entries, they are compared against each sink. If a log entry matches a sink's filter, then a copy of the log entry is written to the destination.

  Sinks can be configured to export logs in storage buckets. It is recommended to configure a data retention policy for these cloud storage buckets and to lock the data retention policy; thus permanently preventing the policy from being reduced or removed. This way, if the system is ever compromised by an attacker or a malicious insider who wants to cover their tracks, the activity logs are definitely preserved for forensics and security investigations.`,
  remediation: `**From Console:**

  1. If sinks are **not** configured, first follow the instructions in the recommendation: *Ensure that sinks are configured for all Log entries.*
  2. For each storage bucket configured as a sink, go to the Cloud Storage browser at https://console.cloud.google.com/storage/browser/<BUCKET_NAME>.
  3. Select the Bucket Lock tab near the top of the page.
  4. In the Retention policy entry, click the Add Duration link. The *Set a retention policy* dialog box appears.
  5. Enter the desired length of time for the retention period and click *Save policy*.
  6. Set the *Lock status* for this retention policy to *Locked*.

  **From Command Line:**

  1. To list all sinks destined to storage buckets:

          gcloud logging sinks list --folder=FOLDER_ID | --organization=ORGANIZATION_ID | --project=PROJECT_ID

  2. For each storage bucket listed above, set a retention policy and lock it:

          gsutil retention set [TIME_DURATION] gs://[BUCKET_NAME]
          gsutil retention lock gs://[BUCKET_NAME]

  For more information, visit https://cloud.google.com/storage/docs/using-bucket-lock#set-policy.`,
  references: [
    'https://cloud.google.com/storage/docs/bucket-lock',
    'https://cloud.google.com/storage/docs/using-bucket-lock',
  ],
  gql: `{
    querygcpProject {
      id
      __typename
      logSinks {
        destination
      }
      logBuckets {
        name
        retentionDays
        locked
      }
    }
  }`,
  resource: 'querygcpProject[*]',
  severity: 'unknown',
  conditions: {
    jq: ` {
            "id": .id,
            "logSinks" : [
              {
                  "destination" :
                      .logSinks[].destination
                      | select(startswith("storage.googleapis.com/"))
                      | sub("storage.googleapis.com/"; "") ,
                  "logBuckets" :.logBuckets
              }
            ] | map({
                "destination" : .destination,
                "logBuckets" : [. as $parent | .logBuckets[] | select($parent.destination == .name)]
              })
          }`,
    path: '@',
    and: [
      {
        path: '[*].logSinks',
        array_all: {
          and: [
            {
              path: '[*].logBuckets',
              isEmpty: false,
            },
            {
              path: '[*].logBuckets',
              array_any: {
                and: [
                  {
                    path: '[*].retentionDays',
                    greaterThan: 0,
                  },
                  {
                    path: '[*].locked',
                    equal: true,
                  },
                ],
              },
            },
          ],
        },
      },
    ],
  },
}
