export default {
  id: 'gcp-cis-1.2.0-6.2.2',
  description:
    "GCP CIS 6.2.2 Ensure 'log_error_verbosity' database flag for Cloud SQL PostgreSQL instance is set to 'DEFAULT' or stricter",
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
                    equal: 'log_error_verbosity',
                  },
                  {
                    path: '[*].value',
                    in: ['default', 'terse'],
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
