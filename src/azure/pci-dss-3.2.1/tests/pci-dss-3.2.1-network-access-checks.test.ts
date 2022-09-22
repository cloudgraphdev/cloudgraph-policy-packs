import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Azure_PCI_DSS_321_Network_access_1 from '../rules/pci-dss-3.2.1-network-access-check-1'
import Azure_PCI_DSS_321_Network_access_2 from '../rules/pci-dss-3.2.1-network-access-check-2'
import Azure_PCI_DSS_321_Network_access_3 from '../rules/pci-dss-3.2.1-network-access-check-3'
import Azure_PCI_DSS_321_Network_access_4 from '../rules/pci-dss-3.2.1-network-access-check-4'

export interface FirewallRules {
  startIpAddress: string | undefined
  endIpAddress: string | undefined
}
export interface queryazureMySqlServer {
  id: string
  firewallRules?: FirewallRules[]
}
export interface queryazurePostgreSqlServer {
  id: string
  firewallRules?: FirewallRules[]
}
export interface QueryazureSqlServer {
  id: string
  firewallRules?: FirewallRules[]
}
export interface Logging {
  read: boolean
  write: boolean
  delete: boolean
}
export interface QueueServiceProperties {
  logging: Logging
}
export interface BlobServiceProperties {
  deleteRetentionPolicyEnabled: boolean
  deleteRetentionPolicyDays: number | null
}
export interface QueryazureStorageAccount {
  id: string
  enableHttpsTrafficOnly?: string
  allowBlobPublicAccess?: string
  networkRuleSetDefaultAction?: string
  encryptionKeySource?: string
  blobServiceProperties?: BlobServiceProperties
  queueServiceProperties?: QueueServiceProperties
}
export interface PCIQueryResponse {
  queryazureSqlServer?: QueryazureSqlServer[]
  queryazureMySqlServer?: queryazureMySqlServer[]
  queryazurePostgreSqlServer?: queryazurePostgreSqlServer[]
  queryazureStorageAccount?: QueryazureStorageAccount[]
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'PCI')
  })

  describe('Network Access Check 1: MySQL Database server firewall rules should not permit start and end IP addresses to be 0.0.0.0', () => {
    const getTestRuleFixture = (
      startIpAddress?: string,
      endIpAddress?: string
    ): PCIQueryResponse => {
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
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Network_access_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when no MySQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('127.0.0.0', '127.255.255.255')

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when there no are any firewall configured', async () => {
      const data: PCIQueryResponse = getTestRuleFixture()
      const sqlServer = data.queryazureMySqlServer?.[0] as queryazureMySqlServer
      sqlServer.firewallRules = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when MySQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('0.0.0.0', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when MySQL Databases allow ingress 255.255.255.255/0 (ANY IP)', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('255.255.255.255', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Network Access Check 2: PostgreSQL Database server firewall rules should not permit start and end IP addresses to be 0.0.0.0', () => {
    const getTestRuleFixture = (
      startIpAddress?: string,
      endIpAddress?: string
    ): PCIQueryResponse => {
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
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Network_access_2 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when no PostgreSQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('127.0.0.0', '127.255.255.255')

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when there no are any firewall configured', async () => {
      const data: PCIQueryResponse = getTestRuleFixture()
      const sqlServer = data.queryazurePostgreSqlServer?.[0] as queryazurePostgreSqlServer
      sqlServer.firewallRules = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when PostgreSQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('0.0.0.0', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when PostgreSQL Databases allow ingress 255.255.255.255/0 (ANY IP)', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('255.255.255.255', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Network Access Check 3: SQL Server firewall rules should not permit start and end IP addresses to be 0.0.0.0', () => {
    const getTestRuleFixture = (
      startIpAddress?: string,
      endIpAddress?: string
    ): PCIQueryResponse => {
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
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Network_access_3 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when no SQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('127.0.0.0', '127.255.255.255')

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when there no are any firewall configured', async () => {
      const data: PCIQueryResponse = getTestRuleFixture()
      const sqlServer = data.queryazureSqlServer?.[0] as QueryazureSqlServer
      sqlServer.firewallRules = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when SQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('0.0.0.0', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when SQL Databases allow ingress 255.255.255.255/0 (ANY IP)', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('255.255.255.255', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Network Access Check 4: Ensure default network access rule for Storage Accounts is set to deny', () => {
    const getTestRuleFixture = (
      networkRuleSetDefaultAction: string
    ): PCIQueryResponse => {
      return {
        queryazureStorageAccount: [
          {
            id: cuid(),
            networkRuleSetDefaultAction
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
        Azure_PCI_DSS_321_Network_access_4 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when default network access rule for Storage Accounts is set to "Deny"', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Deny')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when default network access rule for Storage Accounts is set to "Allow"', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Allow')

      await testRule(data, Result.FAIL)
    })
  })
  
})
