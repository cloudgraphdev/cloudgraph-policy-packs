export default {
  id: 'azure-pci-dss-3.2.1-networking-check-2',  
  title: 'Networking Check 2: Virtual Network security groups attached to SQL Server instances should not permit ingress from 0.0.0.0/0 to all ports and protocols',
  
  description: 'To reduce the potential attack surface for a SQL server, firewall rules should be defined with more granular IP addresses by referencing the range of addresses available from specific data centers.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**Azure Portal**
  
  - Navigate to Virtual Machines and select the VM that has the problem.
  - In the left navigation, select Networking.
  - Select the Inbound port rules tab and delete any inbound rules that permit ingress from ‘0.0.0.0/0’ to all ports and protocols.
  
  **Azure CLI**
  
  Remove the rule(s) that permit ingress from ‘0.0.0.0/0’ to to all ports and protocols:
  
      {
          az network nsg rule delete [--ids]
                                  [--name]
                                  [--nsg-name]
                                  [--resource-group]
                                  [--subscription]
      }`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/virtual-network/security-overview',
      'https://docs.microsoft.com/en-us/cli/azure/network/nsg/rule?view=azure-cli-latest#az-network-nsg-rule-delete',
  ],
  gql: `{
    queryazureSqlServer {
      id
      __typename
      firewallRules {
        startIpAddress
        endIpAddress
      }
    }
  }`,
  resource: 'queryazureSqlServer[*]',
  severity: 'high',
  conditions: {
    not: {
      path: '@.firewallRules',
      array_any: {
        or: [
          {
            path: '[*].startIpAddress',
            equal: '0.0.0.0',
          },
          {
            and: [
              {
                path: '[*].startIpAddress',
                equal: '255.255.255.255',
              },
              {
                path: '[*].endIpAddress',
                equal: '0.0.0.0',
              },
            ],
          }
        ],
      },
    },
  },
}
