import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Azure_PCI_DSS_321_Networking_1 from '../rules/pci-dss-3.2.1-networking-check-1'
import Azure_PCI_DSS_321_Networking_2 from '../rules/pci-dss-3.2.1-networking-check-2'
import Azure_PCI_DSS_321_Networking_3 from '../rules/pci-dss-3.2.1-networking-check-3'

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

export interface SecurityRules {
  access: string | undefined
  destinationPortRange: string | undefined
  direction: string | undefined
  protocol: string | undefined
  sourceAddressPrefix: string | undefined
}

export interface FlowLogs {
  retentionPolicyEnabled?: boolean | undefined
  retentionPolicyDays?: number | undefined
}

export interface QueryazureNetworkSecurityGroup {
  id: string
  securityRules?: SecurityRules[]
  flowLogs?: FlowLogs[]
}

export interface PCIQueryResponse {
  queryazureVirtualMachine?: QueryazureVirtualMachine[]
  queryazureSqlServer?: QueryazureSqlServer[]
  queryazureNetworkSecurityGroup?: QueryazureNetworkSecurityGroup[]
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'PCI')
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

  describe('Networking Check 3: Virtual Network security groups should not permit ingress from 0.0.0.0/0 to TCP/UDP port 22 (SSH)', () => {
    const getTestRuleFixture = (
      access?: string,
      destinationPortRange?: string,
      direction?: string,
      protocol?: string,
      sourceAddressPrefix?: string
    ): PCIQueryResponse => {
      return {
        queryazureNetworkSecurityGroup: [
          {
            id: cuid(),
            securityRules: [
              {
                access,
                destinationPortRange,
                direction,
                protocol,
                sourceAddressPrefix,
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Networking_3 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when SSH access is restricted from the internet', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Deny', '22', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.PASS)
    })
    test('No Security Issue when SSH access is restricted from the internet (No inbound rules configured)', async () => {
      const data: PCIQueryResponse = getTestRuleFixture()
      const securityGroup = data.queryazureNetworkSecurityGroup?.[0] as QueryazureNetworkSecurityGroup
      securityGroup.securityRules = []
      await testRule(data, Result.PASS)
    })
    test('Security Issue when there is an inbound rule with destinationPortRange equal to 22', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })
    test('Security Issue when there is an inbound rule with destinationPortRange equal to *', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Allow', '*', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })
    test('Security Issue when there is an inbound rule with destinationPortRange containing port 22', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Allow', '["3389-3390","22","23"]', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })
    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to *', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', '*')

      await testRule(data, Result.FAIL)
    })
    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to 0.0.0.0,', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })
    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to <nw>/0,', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', '<nw>/0')

      await testRule(data, Result.FAIL)
    })
    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to Internet,', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to any,', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', 'any')

      await testRule(data, Result.FAIL)
    })
  })
})
