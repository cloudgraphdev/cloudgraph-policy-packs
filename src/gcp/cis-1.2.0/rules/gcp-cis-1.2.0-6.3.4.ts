export default {
  id: 'gcp-cis-1.2.0-6.3.4',
  description:
    "GCP CIS 6.3.4 Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured",
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
  severity: 'high',
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
          or: [
            {
              path: '[*].settings.databaseFlags',
              isEmpty: true,
            },
            {
              path: '[*].settings.databaseFlags',
              array_all: {
                not: {
                  and: [
                    {
                      path: '[*].name',
                      equal: 'user options',
                    },
                    {
                      path: '[*].value',
                      notIn: [null, ''],
                    },
                  ],
                },
              },
            },
          ],
        },
      },
    ],
  },
}
