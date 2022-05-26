export default {
  id: 'azure-cis-1.3.1-4.3.7',
  title: 'Azure CIS 4.3.7 Ensure server parameter \'log_retention_days\' is greater than 3 days for PostgreSQL Database Server',

  description: 'Enable log_retention_days on PostgreSQL Servers.',

  audit: `**From Azure Console**

  1. Login to Azure Portal using https://portal.azure.com
  2. Go to Azure Database for PostgreSQL server
  3. For each database, click on Server parameters
  4. Search for log_retention_days.
  5. Ensure that value greater than 3.

  **Using Azure Command Line Interface 2.0**

  Ensure log_retention_days value is greater than 3.

      az postgres server configuration show --resource-group <resourceGroupName> --server-name <serverName> --name log_retention_days`,

  rationale: 'Enabling log_retention_days helps PostgreSQL Database to Sets number of days a log file is retained which in turn generates query and error logs. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.',

  remediation: `**From Azure Console**

  1. Login to Azure Portal using https://portal.azure.com
  2. Go to Azure Database for PostgreSQL server
  3. For each database, click on Server parameters
  4. Search for log_retention_days.
  5. Enter value in range 4-7 (inclusive) and save.

  **Using Azure Command Line Interface 2.0**

  Use the below command to update log_retention_days configuration.

      az postgres server configuration set --resource-group <resourceGroupName> --server-name <serverName> --name log_retention_days --value <4-7>`,

  references: [
      'https://docs.microsoft.com/en-us/azure/postgresql/howto-configure-server-parameters-using-portal',
      'https://docs.microsoft.com/en-us/rest/api/postgresql/configurations/listbyserver',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-6-configure-log-storage-retention',
  ],
  severity: 'medium',
  gql: `{
    queryazurePostgreSqlServer{
      id
      __typename
      configurations{
        name
        value
      }
    }
  }`,
  resource: 'queryazurePostgreSqlServer[*]',
  conditions: {
    path: '@.configurations',
    array_any:{
      path: '[*]',
      and: [
        {
          path: '[*].name',
          equal: 'log_retention_days',
        },
        {
          path: '[*].value',
          greaterThan: 3,
        },
      ],
    }
  },
}
