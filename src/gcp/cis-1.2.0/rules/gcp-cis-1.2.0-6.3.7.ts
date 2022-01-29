export default {
  id: 'gcp-cis-1.2.0-6.3.7',
  description:
    // eslint-disable-next-line max-len
    "GCP CIS 6.3.7 Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is set to 'off'",
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
                    equal: 'contained database authentication',
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
