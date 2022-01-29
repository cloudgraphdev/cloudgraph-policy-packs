export default {
  id: 'gcp-cis-1.2.0-6.2.16',
  description:
    "GCP CIS 6.2.16 Ensure that the 'log_min_duration_statement' database flag for Cloud SQL PostgreSQL instance is set to '-1' (disabled)",
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
                    equal: 'log_min_duration_statement',
                  },
                  {
                    path: '[*].value',
                    equal: '-1',
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
