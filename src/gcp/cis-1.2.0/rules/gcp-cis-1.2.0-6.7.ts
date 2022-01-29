export default {
  id: 'gcp-cis-1.2.0-6.7',
  description:
    'GCP CIS 6.7 Ensure that Cloud SQL database instances are configured with automated backups',
  audit: ``,
  rationale: ``,
  remediation: ``,
  references: [],
  gql: `{
    querygcpSqlInstance{
      id
      __typename
      name
      settings {
        backupConfiguration {
          enabled
          startTime
        }
      }
    }
  }`,
  resource: 'querygcpSqlInstance[*]',
  severity: 'high',
  conditions: {
    and: [
      {
        path: '@.settings.backupConfiguration.enabled',
        equal: true,
      },
      {
        path: '@.settings.backupConfiguration.startTime',
        notIn: [null, false],
      },
    ],
  },
}
