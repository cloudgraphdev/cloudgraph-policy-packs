export default {
  id: 'azure-cis-1.3.1-6.6',
  title: 'Azure CIS 6.6 Ensure that UDP Services are restricted from the Internet',
  
  description: 'Disable Internet exposed UDP ports on network security groups.',
  
  audit: `**From Azure Console**
  
  1. Open the Networking blade for the specific Virtual machine in Azure portal
  2. Verify that the INBOUND PORT RULES does not have a rule for UDP such as
  
      - protocol = UDP,
      - Source = Any OR Internet
  
  **Using Azure Command Line Interface 2.0**  
  List Network security groups with corresponding non-default Security rules:
  
      az network nsg list --query [*].[name,securityRules]
  
  Ensure that none of the NSGs have security rule as below
  
      "access" : "Allow"
      "destinationPortRange" : "*" or "[port range containing 53, 123, 161, 389, 1900, or other configured UDP-based services]"
      "direction" : "Inbound"
      "protocol" : "UDP"
      "sourceAddressPrefix" : "*" or "0.0.0.0" or "<nw>/0" or "/0" or "internet" or "any"`,
  
  rationale: 'The potential security problem with broadly exposing UDP services over the Internet is that attackers can use DDoS amplification techniques to reflect spoofed UDP traffic from Azure Virtual Machines. The most common types of these attacks use exposed DNS, NTP, SSDP, SNMP, CLDAP and other UDP-based services as amplification source for disrupting services of other machines on the Azure Virtual Network or even attack networked devices outside of Azure.',
  
  remediation: `Disable direct UDP access to your Azure Virtual Machines from the Internet. After direct UDP access from the Internet is disabled, you have other options you can use to access UDP based services running on these virtual machines::
    
  - [Point-to-site VPN](https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-point-to-site-resource-manager-portal)
  - [Site-to-site VPN](https://docs.microsoft.com/en-us/azure/vpn-gateway/tutorial-site-to-site-portal)
  - [ExpressRoute](https://docs.microsoft.com/en-us/azure/expressroute/)`,
  
  references: [
      'https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices#secure-your-critical-azure-service-resources-to-only-your-virtual-networks',
      'https://docs.microsoft.com/en-us/azure/security/fundamentals/ddos-best-practices',
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
                equal: '*'
              },
              {
                path: '[*].destinationPortRange', 
                match: /53|123|161|389|1900/
              }
            ]
          },
          { 
            path: '[*].direction', 
            in: ['Inbound', 'inbound']
          },
          { 
            path: '[*].protocol', 
            in: ['UDP', 'Udp']
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
