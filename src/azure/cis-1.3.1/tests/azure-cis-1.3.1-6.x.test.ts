/* eslint-disable max-len */
import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_CIS_131_61 from '../rules/azure-cis-1.3.1-6.1'
import Azure_CIS_131_62 from '../rules/azure-cis-1.3.1-6.2'
import Azure_CIS_131_63 from '../rules/azure-cis-1.3.1-6.3'
import Azure_CIS_131_64 from '../rules/azure-cis-1.3.1-6.4'
import Azure_CIS_131_65 from '../rules/azure-cis-1.3.1-6.5'
import Azure_CIS_131_66 from '../rules/azure-cis-1.3.1-6.6'
import { initRuleEngine } from '../../../utils/test'

export interface FlowLogs {
  retentionPolicyEnabled?: boolean | undefined
  retentionPolicyDays?: number | undefined
}

export interface SecurityRules {
  access: string | undefined
  destinationPortRange: string | undefined
  direction: string | undefined
  protocol: string | undefined
  sourceAddressPrefix: string | undefined
}
export interface QueryazureNetworkSecurityGroup {
  id: string
  securityRules?: SecurityRules[]
  flowLogs?: FlowLogs[]
}

export interface FirewallRules {
  startIpAddress: string | undefined
  endIpAddress: string | undefined
}

export interface QueryazureSqlServer {
  id: string
  firewallRules?: FirewallRules[]
}

export interface VirtualNetwork {
  id: string
}

export interface QueryazureResourceGroup {
  id: string
  virtualNetworks?: VirtualNetwork[]
}
export interface CIS6xQueryResponse {
  queryazureNetworkSecurityGroup?: QueryazureNetworkSecurityGroup[]
  queryazureSqlServer?: QueryazureSqlServer[]
  queryazureResourceGroup?: QueryazureResourceGroup[]
}

describe('CIS Microsoft Azure Foundations: 1.3.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'CIS')
  })

  describe('Azure CIS 6.1 Ensure that RDP access is restricted from the internet', () => {
    const getTestRuleFixture = (
      access?: string,
      destinationPortRange?: string,
      direction?: string,
      protocol?: string,
      sourceAddressPrefix?: string,
    ): CIS6xQueryResponse => {
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
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_61 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when RDP access is restricted from the internet', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Deny', '3389', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when RDP access is restricted from the internet (No inbound rules configured)', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture()
      const securityGroup = data.queryazureNetworkSecurityGroup?.[0] as QueryazureNetworkSecurityGroup
      securityGroup.securityRules = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with destinationPortRange equal to 3389', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '3389', 'Inbound', 'Tcp', 'internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with destinationPortRange equal to *', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '*', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with destinationPortRange containing port 3389', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '["3389-3390"]', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to *', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '3389', 'Inbound', 'Tcp', '*')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to 0.0.0.0,', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '3389', 'Inbound', 'Tcp', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to <nw>/0,', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '3389', 'Inbound', 'Tcp', '<nw>/0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to Internet,', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '3389', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to any,', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '3389', 'Inbound', 'Tcp', 'any')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 6.2 Ensure that SSH access is restricted from the internet', () => {
    const getTestRuleFixture = (
      access?: string,
      destinationPortRange?: string,
      direction?: string,
      protocol?: string,
      sourceAddressPrefix?: string
    ): CIS6xQueryResponse => {
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
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_62 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when SSH access is restricted from the internet', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Deny', '22', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when SSH access is restricted from the internet (No inbound rules configured)', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture()
      const securityGroup = data.queryazureNetworkSecurityGroup?.[0] as QueryazureNetworkSecurityGroup
      securityGroup.securityRules = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with destinationPortRange equal to 22', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with destinationPortRange equal to *', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '*', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with destinationPortRange containing port 22', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '["3389-3390","22","23"]', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to *', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', '*')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to 0.0.0.0,', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to <nw>/0,', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', '<nw>/0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to Internet,', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to any,', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', 'any')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 6.3 Ensure no SQL Databases allow ingress 0.0.0.0/0 (ANY IP)', () => {
    const getTestRuleFixture = (
      startIpAddress?: string,
      endIpAddress?: string
    ): CIS6xQueryResponse => {
      return {
        queryazureSqlServer: [
          {
            id: cuid(),
            firewallRules: [
              {
                startIpAddress,
                endIpAddress
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_63 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when no SQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('127.0.0.0', '127.255.255.255')

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when there no are any firewall configured', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture()
      const sqlServer = data.queryazureSqlServer?.[0] as QueryazureSqlServer
      sqlServer.firewallRules = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when SQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('0.0.0.0', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when SQL Databases allow ingress 255.255.255.255/0 (ANY IP)', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('255.255.255.255', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 6.4 Ensure that Network Security Group Flow Log retention period is "greater than 90 days"', () => {
    const getTestRuleFixture = (
      retentionPolicyEnabled?: boolean,
      retentionPolicyDays?: number
    ): CIS6xQueryResponse => {
      return {
        queryazureNetworkSecurityGroup: [
          {
            id: cuid(),
            flowLogs: [
              {
                retentionPolicyEnabled,
                retentionPolicyDays
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_64 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Network Security Group Flow Log is Enabled and retention period is "greater than 90 days"', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture(true, 91)

      await testRule(data, Result.PASS)
    })

    test('Security Issue when Network Security Group Flow Log is Enabled and retention period is "less than or equal to 90 days"', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture(true, 90)

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when Network Security Group Flow Log is Disabled', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture(false, 0)

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there no are any Network Security Group Flow Log configured', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture()
      const securityGroup = data.queryazureNetworkSecurityGroup?.[0] as QueryazureNetworkSecurityGroup
      securityGroup.flowLogs = []
      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 6.5 Ensure that Network Watcher is Enabled', () => {
    const getTestRuleFixture = (
      enabled: boolean,
    ): CIS6xQueryResponse => {
      return {
        queryazureResourceGroup: [
          {
            id: cuid(),
            virtualNetworks: enabled? [
              {
                id: cuid(),
              },
            ]: undefined,
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_65 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Network Watcher is enabled', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture(
        true,
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when Network Watcher is disabled', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture(
        false,
      )

      await testRule(data, Result.FAIL)
    })
  })


  describe('Azure CIS 6.6 Ensure that UDP Services are restricted from the Internet', () => {
    const getTestRuleFixture = (
      access?: string,
      destinationPortRange?: string,
      direction?: string,
      protocol?: string,
      sourceAddressPrefix?: string
    ): CIS6xQueryResponse => {
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
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_66 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when UDP Services are restricted from the Internet', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Deny', '*', 'Inbound', 'Udp', 'internet')

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when UDP Services are restricted from the Internet (No inbound rules configured)', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture()
      const securityGroup = data.queryazureNetworkSecurityGroup?.[0] as QueryazureNetworkSecurityGroup
      securityGroup.securityRules = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with destinationPortRange equal to *', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '*', 'Inbound', 'Udp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with destinationPortRange containing port 161', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '["53","123","161", "389", "1900"]', 'Inbound', 'Udp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to *', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '*', 'Inbound', 'UDP', '*')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to 0.0.0.0,', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('allow', '*', 'inbound', 'Udp', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to <nw>/0,', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '*', 'Inbound', 'Udp', '<nw>/0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to Internet,', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '*', 'Inbound', 'Udp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to any,', async () => {
      const data: CIS6xQueryResponse = getTestRuleFixture('Allow', '*', 'Inbound', 'Udp', 'Any')

      await testRule(data, Result.FAIL)
    })
  })
})
