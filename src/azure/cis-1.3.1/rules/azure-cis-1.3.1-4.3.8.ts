export default {
  id: 'azure-cis-1.3.1-4.3.8',
  title:
    'Azure CIS 4.3.8 Ensure \'Allow access to Azure services\' for PostgreSQL Database Server is disabled',

  description:
    'Disable access from Azure services to PostgreSQL Database Server',

  audit: `**From Azure Console**

  1. Login to Azure Portal using https://portal.azure.com
  2. Go to Azure Database for PostgreSQL server
  3. For each database, click on Connection security
  4. In Firewall rules
  5. Ensure Allow access to Azure services is set to OFF.

  **Using Azure Command Line Interface 2.0**

  Ensure the output of the below command does not include a rule with the name AllowAllAzureIps or "startIpAddress": "0.0.0.0" & "endIpAddress": "0.0.0.0",

      az postgres server firewall-rule list --resource-group <resourceGroupName> --server <serverName>`,

  rationale:
    "If access from Azure services is enabled, the server's firewall will accept connections from all Azure resources, including resources not in your subscription. This is usually not a desired configuration. Instead, setup firewall rules to allow access from specific network ranges or VNET rules to allow access from specific virtual networks.",

  remediation: `**From Azure Console**

  1. Login to Azure Portal using https://portal.azure.com
  2. Go to Azure Database for PostgreSQL server
  3. For each database, click on Connection security
  4. In Firewall rules
  5. Ensure Allow access to Azure services is set to OFF.
  6. Click Save to apply the changed rule.

  **Using Azure Command Line Interface 2.0**

  Use the below command to delete the AllowAllAzureIps rule for PostgreSQL Database.

      az postgres server firewall-rule delete --name AllowAllAzureIps --resourcegroup <resourceGroupName> --server-name <serverName>`,

  references: [
    'https://docs.microsoft.com/en-us/azure/postgresql/howto-configure-server-parameters-using-portal',
    'https://docs.microsoft.com/en-us/rest/api/postgresql/configurations/listbyserver',
    'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-logging-threat-detection#lt-6-configure-log-storage-retention',
  ],
  severity: 'medium',
  gql: `{
    queryazurePostgreSqlServer {
      id
      __typename
      firewallRules {
        name
        startIpAddress
        endIpAddress
      }
    }
  }`,
  resource: 'queryazurePostgreSqlServer[*]',
  conditions: {
    path: '@.firewallRules',
    not: {
      array_any: {
        or: [
          {
            path: '[*].name',
            equal: 'AllowAllAzureIps',
          },
          {
            and: [
              {
                path: '[*].startIpAddress',
                equal: '0.0.0.0',
              },
              {
                path: '[*].endIpAddress',
                equal: '0.0.0.0',
              },
            ]
          }
        ],
      }
    }
  },
}
