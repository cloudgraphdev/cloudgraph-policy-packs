export default {
  id: 'gcp-cis-1.2.0-2.3',
  description:
    'GCP CIS 2.3 Ensure that retention policies on log buckets are configured using Bucket Lock',
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
    `https://cloud.google.com/storage/docs/bucket-lock`,
    `https://cloud.google.com/storage/docs/using-bucket-lock`,
  ],
  gql: `{
    querygcpProject {
      id
      __typename
      logSink {
        destination
      }
      logBucket {
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
            "logSink" : [
              {
                  "destination" :
                      .logSink[].destination
                      | select(startswith("storage.googleapis.com/"))
                      | sub("storage.googleapis.com/"; "") ,
                  "logBuckets" :.logBucket
              }
            ] | map({
                "destination" : .destination,
                "logBuckets" : [. as $parent | .logBuckets[] | select($parent.destination == .name)]
              })
          }`,
    path: '@',
    and: [
      {
        path: '[*].logSink',
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
