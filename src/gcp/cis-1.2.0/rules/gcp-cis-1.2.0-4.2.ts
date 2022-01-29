export default {
  id: 'gcp-cis-1.2.0-4.2',
  description:
    'GCP CIS 4.2 Ensure that instances are not configured to use the default service account with full access to all Cloud APIs',
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
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
        scopes
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
        | {"match" : (length > 0), "scopes": .[].scopes} // {"match" : false, "scopes": []}`,
        path: '@',
        and: [
          {
            path: '@.match',
            notEqual: true,
          },
          {
            path: '[*].scopes',
            array_all: {
              notEqual: 'https://www.googleapis.com/auth/cloud-platform',
            },
          },
        ],
      },
    ],
  },
}
