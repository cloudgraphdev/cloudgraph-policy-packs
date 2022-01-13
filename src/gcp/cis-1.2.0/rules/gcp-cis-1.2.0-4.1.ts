export default {
  id: 'gcp-cis-1.2.0-4.1',
  description:
    'GCP CIS 4.1 Ensure that instances are not configured to use the default service account',
  gql: `{
    querygcpVmInstance{
      __typename
      id
      project{
        id
      }
      name
      labels{
        value
      }
      serviceAccounts{
        email
      }
    }
  }`,
  resource: 'querygcpVmInstance[*]',
  severity: 'medium',
  conditions: {
    path: '@',
    or: [
      {
        path: '@',
        and: [
          {
            path: '[*].name',
            match: /^gke-.*$/,
          },
          {
            path: '[*].labels',
            array_any: {
              path: '[*].value',
              equal: 'goog-gke-node',
            },
          },
        ],
      },
      {
        jq: `[{ "defaultEmail" : (.project[].id | split("/") | .[1] + "-compute@developer.gserviceaccount.com")} + .serviceAccounts[]]
        | [.[] | select(.defaultEmail == .email) ]
        | {"match" : (length > 0)}`,
        path: '@',
        and: [
          {
            path: '@.match',
            notEqual: true,
          },
        ],
      },
    ],
  },
}
