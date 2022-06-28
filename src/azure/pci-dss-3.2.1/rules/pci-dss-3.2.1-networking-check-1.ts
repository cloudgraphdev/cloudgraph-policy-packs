export default {
  id: 'azure-pci-dss-3.2.1-networking-check-1',  
  title: 'Networking Check 1: Virtual Network security groups should not permit ingress from ‘0.0.0.0/0’ to TCP port 3389 (RDP)',
  
  description: 'The potential security problem with using RDP over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use a virtual machine as a launch point for compromising other machines on an Azure Virtual Network or even attack networked devices outside of Azure.',
  
  audit: '',
  
  rationale: '',
  
  remediation: `**Azure Portal**
  
  - Navigate to Virtual Machines and select the VM that has the problem.
  - In the left navigation, select Networking.
  - Select the Inbound port rules tab and delete any inbound rules that permit ingress from ‘0.0.0.0/0’ to TCP port 3389 (RDP).
  
  **Azure CLI**
  
  Remove the rule(s) that permit ingress from ‘0.0.0.0/0’ to TCP port 3389 (RDP):
  
      az network nsg rule delete -g MyResourceGroup --nsg-name MyNsg -n MyNsgRule
  
  Azure Resource Manager
  Ensure that a Microsoft.Network/networkSecurityGroups/securityRules or Microsoft.Network/networkSecurityGroupsdoes NOT contain all of the following:
  
  - "sourceAddressPrefixes": "*" or "0.0.0.0" or "internet" or "any"
  
  - "destination_port_range": "3389" or "*"`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/virtual-network/security-overview',
      'https://docs.microsoft.com/en-us/cli/azure/network/nsg/rule?view=azure-cli-latest#az-network-nsg-rule-delete',
  ],
  gql: `{
    queryazureVirtualMachine {
      id
      __typename
      networkInterfaces {
        securityGroups {
          securityRules {
            direction
            access
            protocol
            sourceAddressPrefix
            sourceAddressPrefixes
            destinationPortRange
            destinationPortRanges
          }
        }
      }
    }
  }`,
  resource: 'queryazureVirtualMachine[*]',
  severity: 'high',
  conditions: {
    not: {
      path: '@.networkInterfaces',
      array_any: {
        path: '[*].securityGroups',
        array_any: {
          path: '[*].securityRules',
          array_any: {
            and: [
              {
                path: '[*].access',
                equal: 'Allow',
              },
              {
                path: '[*].direction',
                equal: 'Inbound',
              },
              {
                path: '[*].protocol',
                in: ['TCP', 'Tcp', '*'],
              },
              {
                or: [
                  {
                    path: '[*].sourceAddressPrefix',
                    in: ['0.0.0.0', '0.0.0.0/0', '::/0', 'any', 'internet', '<nw>/0', '/0', '*'],
                  },
                  {
                    path: '[*].sourceAddressPrefixes',
                    contains: '0.0.0.0',
                  },
                  {
                    path: '[*].sourceAddressPrefixes',
                    contains: '0.0.0.0/0',
                  },
                  {
                    path: '[*].sourceAddressPrefixes',
                    contains: '::/0',
                  },
                  {
                    path: '[*].sourceAddressPrefixes',
                    contains: 'any',
                  },
                  {
                    path: '[*].sourceAddressPrefixes',
                    contains: 'internet',
                  },
                  {
                    path: '[*].sourceAddressPrefixes',
                    contains: '<nw>/0',
                  },
                  {
                    path: '[*].sourceAddressPrefixes',
                    contains: '/0',
                  },
                  {
                    path: '[*].sourceAddressPrefixes',
                    contains: '*',
                  },
                ],
              },
              {
                or: [
                  {
                    path: '[*].destinationPortRange',
                    in: ['*', '3389'],
                  },
                  {
                    path: '[*].destinationPortRanges',
                    jq: '[(if .[] | length > 0  then .[] else [""][] end  | split("-")  | {fromPort: (.[0] | tonumber), toPort: (.[1] | tonumber // .[0])})]',
                    array_any: {
                      and: [
                        {
                          path: '[*].fromPort',
                          lessThanInclusive: 3389,
                        },
                        {
                          path: '[*].toPort',
                          greaterThanInclusive: 3389,
                        },
                      ],
                    },
                  },
                ],
              },
            ],
          },
        },
      },

    },
  },
}
