// similar to CIS 6.3
export default {
  id: 'pci-dss-3.2.1-network-access-check-2',  
  title: 'Network Access Check 2: PostgreSQL Database server firewall rules should not permit start and end IP addresses to be 0.0.0.0',
  
  description: 'Ensure that no PostgreSQL Databases allow ingress from 0.0.0.0/0 (ANY IP).',
  
  audit: `** From Azure Console**
  
  1. Go to PostgreSQL servers
  2. For each PostgreSQL server
  3. Click on Firewall / Virtual Networks
  4. Ensure that Allow access to Azure services to set to OFF
  5. Ensure that no firewall rule exists with
  
      - Start IP of 0.0.0.0
      - or other combinations which allows access to wider public IP ranges
  
  **Azure CLI**  
  List all firewall rules for a PostgreSQL Database server:

      az postgres server firewall-rule list --resource-group <your-resource-group> --server-name <your-server-name>
  
  Look for rules with a start and end IP address of 0.0.0.0 and copy the rule ID.
  
  Delete the rule:
  
      az postgres server firewall-rule delete --resource-group <your-resource-group> --server-name <your-server-name> --name <your-firewall-name>
  
  To allow specific Azure services to connect to the PostgreSQL Database server, consider setting up a virtual network service endpoint and rules.`,
  
  rationale: `PostgreSQL Server includes a firewall to block access to unauthorized connections. More granular IP addresses can be defined by referencing the range of addresses available from specific datacenters.
  
  By default, for a PostgreSQL server, a Firewall exists with StartIp of 0.0.0.0 and EndIP of 0.0.0.0 allowing access to all the Azure services.
  
  Additionally, a custom rule can be set up with StartIp of 0.0.0.0 and EndIP of 255.255.255.255 allowing access from ANY IP over the Internet.
  
  In order to reduce the potential attack surface for a PostgreSQL server, firewall rules should be defined with more granular IP addresses by referencing the range of addresses available from specific datacenters.`,
  
  remediation: `**From Azure Console**
  
  1. Go to PostgreSQL servers
  2. For each PostgreSQL server
  3. Click on Firewall / Virtual Networks
  4. Set Allow access to Azure services to 'OFF'
  5. Set firewall rules to limit access to only authorized connections`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/postgresql/howto-manage-firewall-using-cli',
      'https://docs.microsoft.com/en-us/azure/postgresql/concepts-firewall-rules#connecting-from-azure',
      'https://docs.microsoft.com/en-us/azure/postgresql/concepts-firewall-rules',
      'https://docs.microsoft.com/en-us/azure/PostgreSQL/concepts-data-access-and-security-vnet',
      'https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-service-endpoints-overview',
  ],  
  gql: `{
    queryazurePostgreSqlServer {
      id
      __typename
      firewallRules {
        startIpAddress
        endIpAddress
      }
    }
  }`,
  resource: 'queryazurePostgreSqlServer[*]',
  severity: 'high',
  conditions: {
    not: {
      path: '@.firewallRules',
      array_any: {
        or: [
          { 
            path: '[*].startIpAddress', 
            equal: '0.0.0.0' 
          },
          { 
            and: [
              {
                path: '[*].startIpAddress', 
                equal: '255.255.255.255' 
              },
              {
                path: '[*].endIpAddress', 
                equal: '0.0.0.0' 
              }
            ]
          },
        ],
      },
    },
  },
}
