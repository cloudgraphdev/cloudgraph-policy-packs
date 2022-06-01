import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Azure_PCI_DSS_321_Networking_1 from '../rules/pci-dss-3.2.1-networking-check-1'
import Azure_PCI_DSS_321_Networking_2 from '../rules/pci-dss-3.2.1-networking-check-2'

const ipV4WildcardAddress = '0.0.0.0/0'
const ipV6WildcardAddress = '::/0'

export interface SecurityRule {
  direction: string
  access: string
  protocol: string
  sourceAddressPrefix: string | undefined
  sourceAddressPrefixes: string[] | undefined
  destinationPortRange: string
  destinationPortRanges: string[]
}

export interface SecurityGroup {
  securityRules: SecurityRule[]
}

export interface NetworkInterface {
  securityGroups: SecurityGroup[]
}

export interface QueryazureVirtualMachine {
  id: string
  networkInterfaces: NetworkInterface[]
}

export interface FirewallRule {
  startIpAddress: string
  endIpAddress: string
}

export interface QueryazureSqlServer {
  id: string
  firewallRules: FirewallRule[]
}

export interface PCIQueryResponse {
  queryazureVirtualMachine?: QueryazureVirtualMachine[]
  queryazureSqlServer?: QueryazureSqlServer[]
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'azure',
      entityName: 'PCI',
    })
  })

  describe('Networking Check 1: Virtual Network security groups should not permit ingress from ‘0.0.0.0/0’ to TCP port 3389 (RDP)', () => {
    const testRule = async (
      fromPort: number | undefined,
      toPort: number | undefined,
      sourceAddressPrefix: string | undefined,
      sourceAddressPrefixes: string[] | undefined,
      expectedResult: Result,
      protocol?: string
    ): Promise<void> => {
      // Arrange
      const data: PCIQueryResponse = {
        queryazureVirtualMachine: [
          {
            id: cuid(),
            networkInterfaces: [
              {
                securityGroups: [
                  {
                    securityRules: [
                      {
                        direction: 'Inbound',
                        access: 'Allow',
                        protocol: protocol || 'TCP',
                        sourceAddressPrefix,
                        sourceAddressPrefixes,
                        destinationPortRange: `${fromPort}`,
                        destinationPortRanges:
                          fromPort && toPort ? [`${fromPort}-${toPort}`] : [],
                      },
                    ],
                  },
                ],
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Networking_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a random IPv4 address and port 3389', async () => {
      await testRule(22, 22, '10.10.10.10/16', undefined, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and port 80', async () => {
      await testRule(80, 80, ipV4WildcardAddress, undefined, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and port 80', async () => {
      await testRule(80, 80, ipV6WildcardAddress, undefined, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port 3389', async () => {
      await testRule(1000, 2000, '10.10.10.10/16', undefined, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and a port range not including the port 3389', async () => {
      await testRule(1000, 2000, ipV4WildcardAddress, undefined, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and a port range not including the port 3389', async () => {
      await testRule(1000, 2000, ipV6WildcardAddress, undefined, Result.PASS)
    })

    test('Security Issue when IPv4 wilcard address and port 3389 and tcp protocol', async () => {
      await testRule(3389, 3389, ipV4WildcardAddress, undefined, Result.FAIL)
    })

    test('Security Issue when IPv4 wilcard address and port 3389 and all protocol', async () => {
      await testRule(
        3389,
        3389,
        ipV4WildcardAddress,
        undefined,
        Result.FAIL,
        '*'
      )
    })

    test('Security Issue when IPv4 wilcard address, Intenet and port 3389 and tcp protocol', async () => {
      await testRule(3389, 3389, undefined, [ipV4WildcardAddress, 'Internet'], Result.FAIL)
    })

    test('Security Issue when IPv6 wilcard address and port 3389 and tcp protocol', async () => {
      await testRule(3389, 3389, ipV6WildcardAddress, undefined, Result.FAIL)
    })

    test('Security Issue when IPv6 wilcard address and port 22 and all protocol', async () => {
      await testRule(
        3389,
        3389,
        ipV6WildcardAddress,
        undefined,
        Result.FAIL,
        '*'
      )
    })

    test('Security Issue when IPv6 wilcard address, Intenet and port 3389 and tcp protocol', async () => {
      await testRule(3389, 3389, undefined, [ipV6WildcardAddress, 'Internet'], Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and port range includes the port 3389', async () => {
      await testRule(3000, 4000, ipV4WildcardAddress, undefined, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and port range includes the port 3389', async () => {
      await testRule(3000, 4000, ipV6WildcardAddress, undefined, Result.FAIL)
    })
  })

  describe('Networking Check 2: Virtual Network security groups attached to SQL Server instances should not permit ingress from 0.0.0.0/0 to all ports and protocols', () => {
    const testRule = async (
      startIpAddress: string,
      endIpAddress: string,
      expectedResult: Result,
    ): Promise<void> => {
      // Arrange
      const data: PCIQueryResponse = {
        queryazureSqlServer: [
          {
            id: cuid(),
            firewallRules: [
              {
                startIpAddress,
                endIpAddress
              }
            ]
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Networking_2 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound that not allow any IP', async () => {
      await testRule('127.0.0.0', '127.255.255.255', Result.PASS)
    })

    test('No Security Issue when there is an inbound that allow any IP', async () => {
      await testRule('255.255.255.255', '0.0.0.0', Result.FAIL)
    })

  })
})
