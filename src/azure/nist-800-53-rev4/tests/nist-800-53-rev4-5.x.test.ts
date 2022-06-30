/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_NIST_800_53_51 from '../rules/azure-nist-800-53-rev4-5.1'
import Azure_NIST_800_53_52 from '../rules/azure-nist-800-53-rev4-5.2'
import Azure_NIST_800_53_53 from '../rules/azure-nist-800-53-rev4-5.3'
import Azure_NIST_800_53_54 from '../rules/azure-nist-800-53-rev4-5.4'
import Azure_NIST_800_53_55 from '../rules/azure-nist-800-53-rev4-5.5'
import Azure_NIST_800_53_56 from '../rules/azure-nist-800-53-rev4-5.6'

export interface FirewallRules {
  startIpAddress: string | undefined
  endIpAddress: string | undefined
}

export interface QueryazureSqlServer {
  id: string
  firewallRules?: FirewallRules[]
}

export interface queryazureMySqlServer {
  id: string
  firewallRules?: FirewallRules[]
}

export interface queryazurePostgreSqlServer {
  id: string
  firewallRules?: FirewallRules[]
}

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

export interface NIST5xQueryResponse {
  queryazureSqlServer?: QueryazureSqlServer[]
  queryazureMySqlServer?: queryazureMySqlServer[]
  queryazurePostgreSqlServer?: queryazurePostgreSqlServer[]
  queryazureNetworkSecurityGroup?: QueryazureNetworkSecurityGroup[]
}

describe('Azure NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'azure',
      entityName: 'NIST',
    })
  })

  describe('Azure NIST 5.1 MySQL Database server firewall rules should not permit start and end IP addresses to be 0.0.0.0', () => {
    const getTestRuleFixture = (
      startIpAddress?: string,
      endIpAddress?: string
    ): NIST5xQueryResponse => {
      return {
        queryazureMySqlServer: [
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
      data: NIST5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_51 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when no MySQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('127.0.0.0', '127.255.255.255')

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when there no are any firewall configured', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture()
      const sqlServer = data.queryazureMySqlServer?.[0] as queryazureMySqlServer
      sqlServer.firewallRules = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when MySQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('0.0.0.0', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when MySQL Databases allow ingress 255.255.255.255/0 (ANY IP)', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('255.255.255.255', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 5.2 PostgreSQL Database server firewall rules should not permit start and end IP addresses to be 0.0.0.0', () => {
    const getTestRuleFixture = (
      startIpAddress?: string,
      endIpAddress?: string
    ): NIST5xQueryResponse => {
      return {
        queryazurePostgreSqlServer: [
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
      data: NIST5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_52 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when no PostgreSQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('127.0.0.0', '127.255.255.255')

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when there no are any firewall configured', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture()
      const sqlServer = data.queryazurePostgreSqlServer?.[0] as queryazurePostgreSqlServer
      sqlServer.firewallRules = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when PostgreSQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('0.0.0.0', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when PostgreSQL Databases allow ingress 255.255.255.255/0 (ANY IP)', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('255.255.255.255', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 5.3 SQL Server firewall rules should not permit start and end IP addresses to be 0.0.0.0', () => {
    const getTestRuleFixture = (
      startIpAddress?: string,
      endIpAddress?: string
    ): NIST5xQueryResponse => {
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
      data: NIST5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_53 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when no SQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('127.0.0.0', '127.255.255.255')

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when there no are any firewall configured', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture()
      const sqlServer = data.queryazureSqlServer?.[0] as QueryazureSqlServer
      sqlServer.firewallRules = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when SQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('0.0.0.0', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when SQL Databases allow ingress 255.255.255.255/0 (ANY IP)', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('255.255.255.255', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 5.4 Virtual Network security groups attached to SQL Server instances should not permit ingress from 0.0.0.0/0 to all ports and protocols', () => {
    const getTestRuleFixture = (
      startIpAddress?: string,
      endIpAddress?: string
    ): NIST5xQueryResponse => {
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
      data: NIST5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_54 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when no SQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('127.0.0.0', '127.255.255.255')

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when there no are any firewall configured', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture()
      const sqlServer = data.queryazureSqlServer?.[0] as QueryazureSqlServer
      sqlServer.firewallRules = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when SQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('0.0.0.0', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when SQL Databases allow ingress 255.255.255.255/0 (ANY IP)', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('255.255.255.255', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 5.5 Virtual Network security groups should not permit ingress from "0.0.0.0/0" to TCP/UDP port 22 (SSH)', () => {
    const getTestRuleFixture = (
      access?: string,
      destinationPortRange?: string,
      direction?: string,
      protocol?: string,
      sourceAddressPrefix?: string
    ): NIST5xQueryResponse => {
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
      data: NIST5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_55 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when SSH access is restricted from the internet', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Deny', '22', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when SSH access is restricted from the internet (No inbound rules configured)', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture()
      const securityGroup = data.queryazureNetworkSecurityGroup?.[0] as QueryazureNetworkSecurityGroup
      securityGroup.securityRules = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with destinationPortRange equal to 22', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with destinationPortRange equal to *', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '*', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with destinationPortRange containing port 22', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '["3389-3390","22","23"]', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to *', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', '*')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to 0.0.0.0,', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to <nw>/0,', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', '<nw>/0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to Internet,', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to any,', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '22', 'Inbound', 'Tcp', 'any')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 5.6 Virtual Network security groups should not permit ingress from "0.0.0.0/0" to TCP/UDP port 3389 (RDP)', () => {
    const getTestRuleFixture = (
      access?: string,
      destinationPortRange?: string,
      direction?: string,
      protocol?: string,
      sourceAddressPrefix?: string,
    ): NIST5xQueryResponse => {
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
      data: NIST5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_56 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when RDP access is restricted from the internet', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Deny', '3389', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when RDP access is restricted from the internet (No inbound rules configured)', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture()
      const securityGroup = data.queryazureNetworkSecurityGroup?.[0] as QueryazureNetworkSecurityGroup
      securityGroup.securityRules = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with destinationPortRange equal to 3389', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '3389', 'Inbound', 'Tcp', 'internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with destinationPortRange equal to *', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '*', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with destinationPortRange containing port 3389', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '["3389-3390"]', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to *', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '3389', 'Inbound', 'Tcp', '*')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to 0.0.0.0,', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '3389', 'Inbound', 'Tcp', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to <nw>/0,', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '3389', 'Inbound', 'Tcp', '<nw>/0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to Internet,', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '3389', 'Inbound', 'Tcp', 'Internet')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with sourceAddressPrefix equal to any,', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Allow', '3389', 'Inbound', 'Tcp', 'any')

      await testRule(data, Result.FAIL)
    })
  })

})