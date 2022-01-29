export default {
  id: 'gcp-cis-1.2.0-6.3.6',
  description:
    "GCP CIS 6.3.6 Ensure '3625 (trace flag)' database flag for Cloud SQL SQL Server instance is set to 'off'",
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
  gql: `{
    querygcpProject{
      id
      projectId
      __typename
      sqlInstances(filter:{ databaseVersion: {regexp:  "/SQLSERVER*/"}}){
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
  severity: 'unknown',
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
                    equal: '3625 (trace flag)',
                  },
                  {
                    path: '[*].value',
                    equal: 'off',
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
