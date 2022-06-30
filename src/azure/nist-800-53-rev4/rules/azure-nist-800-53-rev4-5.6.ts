//similar to CIS 6.1
export default {
  id: 'azure-nist-800-53-rev4-5.6',  
  title: 'Azure NIST 5.6 Virtual Network security groups should not permit ingress from "0.0.0.0/0" to TCP/UDP port 3389 (RDP)',

  description: 'Disable RDP access on network security groups from the Internet.',

  audit: `**From Azure Console**

  1. For each VM, open the Networking blade
  2. Verify that the INBOUND PORT RULES **does not** have a rule for RDP such as

      - port = 3389,
      - protocol = TCP,
      - Source = Any OR Internet

  **Using Azure Command Line Interface 2.0**  
  List Network security groups with corresponding non-default Security rules:

      az network nsg list --query [*].[name,securityRules]

  Ensure that none of the NSGs have security rule as below

      "access" : "Allow"
      "destinationPortRange" : "3389" or "*" or "[port range containing 3389]"
      "direction" : "Inbound"
      "protocol" : "TCP"
      "sourceAddressPrefix" : "*" or "0.0.0.0" or "<nw>/0" or "/0" or "internet" or "any"`,

  rationale: 'The potential security problem with using RDP over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use a virtual machine as a launch point for compromising other machines on an Azure Virtual Network or even attack networked devices outside of Azure.',

  remediation: `Disable direct RDP access to your Azure Virtual Machines from the Internet. After direct RDP access from the Internet is disabled, you have other options you can use to access these virtual machines for remote management:

  - [Point-to-site VPN](https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-point-to-site-resource-manager-portal)
  - [Site-to-site VPN](https://docs.microsoft.com/en-us/azure/vpn-gateway/tutorial-site-to-site-portal)
  - [ExpressRoute](https://docs.microsoft.com/en-us/azure/expressroute/)`,

  references: [
      'https://docs.microsoft.com/en-us/azure/security/azure-security-network-security-best-practices#disable-rdpssh-access-to-azure-virtual-machines',
      'https://docs.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-network-security#ns-1-implement-security-for-internal-traffic',
  ],  
  gql: `{
    queryazureNetworkSecurityGroup {
      id
      __typename
      securityRules {
        access
        destinationPortRange
        direction
        protocol
        sourceAddressPrefix
      }
    }
  }`,
  resource: 'queryazureNetworkSecurityGroup[*]',
  severity: 'high',
  conditions: {
    not: {
      path: '@.securityRules',
      array_any: {
        and: [
          { 
            path: '[*].access', 
            in: ['Allow', 'allow']
          },
          { 
            or: [
              {
                path: '[*].destinationPortRange', 
                in: ['3389', '*'] 
              },
              {
                path: '[*].destinationPortRange', 
                match: /3389/
              }
            ]
          },
          { 
            path: '[*].direction', 
            in: ['Inbound', 'inbound']
          },
          { 
            path: '[*].protocol', 
            in: ['TCP', 'Tcp']
          },
          { 
            path: '[*].sourceAddressPrefix', 
            in: ['*', '0.0.0.0', '<nw>/0', '/0', 'Internet', 'internet', 'Any', 'any'] 
          },
        ],
      },
    },
  },
}
