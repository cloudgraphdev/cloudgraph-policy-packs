export default {
  id: 'gcp-cis-1.2.0-4.3',
  description:
    'GCP CIS 4.3 Ensure "Block Project-wide SSH keys" is enabled for VM instances',
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
      metadata{
        items{
          key
          value
        }
      }
    }
  }`,
  resource: 'querygcpVmInstance[*]',
  severity: 'unknown',
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
        and: [
          {
            path: '[*].metadata.items',
            array_any: {
              and: [
                {
                  path: '[*].key',
                  equal: 'block-project-ssh-keys',
                },
                {
                  path: '[*].value',
                  equal: 'true',
                },
              ],
            },
          },
          {
            jq: `[{ "defaultEmail" : (.project[].id | split("/") | .[1] + "-compute@developer.gserviceaccount.com")} + .serviceAccounts[]]
            | [.[] | select(.defaultEmail == .email) ]
            | {"match" : (length > 0)} // {"match" : false}`,
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
    ],
  },
}
