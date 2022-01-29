export default {
  id: 'gcp-cis-1.2.0-6.2.13',
  description:
    "GCP CIS 6.2.13 Ensure that the 'log_min_messages' database flag for Cloud SQL PostgreSQL instance is set appropriately",
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
  gql: `{
    querygcpProject{
      id
      projectId
      __typename
      sqlInstances(filter:{ databaseVersion: {regexp:  "/POSTGRES*/"}}){
        name
        settings{
          databaseFlags{
            name
            value
          }
        }
      }
    }
  }`,
  resource: 'querygcpProject[*]',
  severity: 'medium',
  conditions: {
    path: '@',
    or: [
      {
        path: '[*].sqlInstances',
        isEmpty: true,
      },
      {
        path: '[*].sqlInstances',
        array_all: {
          path: '[*]',
          and: [
            {
              path: '[*].settings.databaseFlags',
              isEmpty: false,
            },
            {
              path: '[*].settings.databaseFlags',
              array_any: {
                and: [
                  {
                    path: '[*].name',
                    equal: 'log_min_messages',
                  },
                  {
                    path: '[*].value',
                    in: [
                      'DEBUG5',
                      'DEBUG4',
                      'DEBUG3',
                      'DEBUG2',
                      'DEBUG1',
                      'INFO',
                      'NOTICE',
                      'WARNING',
                      'ERROR',
                      'LOG',
                      'FATAL',
                      'PANIC',
                    ],
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
