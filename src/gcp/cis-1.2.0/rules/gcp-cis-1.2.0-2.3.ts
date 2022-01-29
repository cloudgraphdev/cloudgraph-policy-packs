export default {
  id: 'gcp-cis-1.2.0-2.3',
  description:
    'GCP CIS 2.3 Ensure that retention policies on log buckets are configured using Bucket Lock',
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
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
