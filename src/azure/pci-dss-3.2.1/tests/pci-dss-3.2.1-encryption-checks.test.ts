import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Azure_PCI_DSS_321_Encryption_1 from '../rules/pci-dss-3.2.1-encryption-check-1'
import Azure_PCI_DSS_321_Encryption_2 from '../rules/pci-dss-3.2.1-encryption-check-2'
import Azure_PCI_DSS_321_Encryption_3 from '../rules/pci-dss-3.2.1-encryption-check-3'
import Azure_PCI_DSS_321_Encryption_4 from '../rules/pci-dss-3.2.1-encryption-check-4'

export interface SiteConfig {
  minTlsVersion?: string
  http20Enabled?: boolean
  ftpsState?: string
  managedServiceIdentityId?: number | null
}
export interface QueryazureAppServiceWebApp {
  id: string
  name?: string
  httpsOnly?: boolean
  siteConfig?: SiteConfig
  clientCertEnabled?: boolean
  authEnabled?: boolean
  identityPrincipalId?: string | null
}
export interface QueryazureMySqlServer {
  id: string
  sslEnforcement?: string
}
export interface PostgreSqlServerConfiguration {
  name: string
  value: string | number
}
export interface PostgreSqlServerFirewallRules {
  name: string
  startIpAddress: string
  endIpAddress: string
}
export interface QueryazurePostgreSqlServer {
  id: string
  configurations?: PostgreSqlServerConfiguration[]
  firewallRules?: PostgreSqlServerFirewallRules[]
  sslEnforcement?: string
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
  queryazureAppServiceWebApp?: QueryazureAppServiceWebApp[]
  queryazureMySqlServer?: QueryazureMySqlServer[]
  queryazurePostgreSqlServer?: QueryazurePostgreSqlServer[]
  queryazureStorageAccount?: QueryazureStorageAccount[]
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'PCI')
  })

  describe('Encryption Check 1: App Service web apps should have \'HTTPS only\' enabled', () => {
    const getTestRuleFixture = (httpsOnly: boolean): PCIQueryResponse => {
      return {
        queryazureAppServiceWebApp: [
          {
            id: cuid(),
            httpsOnly,
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
        Azure_PCI_DSS_321_Encryption_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a httpsOnly set to On', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true)

      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a httpsOnly set to Off', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(false)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Encryption Check 2: MySQL Database server \'enforce SSL connection\' should be enabled', () => {
    const getTestRuleFixture = (
      sslEnforcement?: string | undefined
    ): PCIQueryResponse => {
      return {
        queryazureMySqlServer: [
          {
            id: cuid(),
            sslEnforcement,
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
        Azure_PCI_DSS_321_Encryption_2 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when \'Enforce SSL connection\' is set to \'ENABLED\' for MySQL Database Server', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Enabled')

      await testRule(data, Result.PASS)
    })

    test('Security Security Issue when \'Enforce SSL connection\' for MySQL Database Server is not configured', async () => {
      const data: PCIQueryResponse = getTestRuleFixture()

      await testRule(data, Result.FAIL)
    })
  })

  describe('Encryption Check 3: PostgreSQL Database server \'enforce SSL connection\' should be enabled', () => {
    const getTestRuleFixture = (
      sslEnforcement?: string | undefined
    ): PCIQueryResponse => {
      return {
        queryazurePostgreSqlServer: [
          {
            id: cuid(),
            sslEnforcement,
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
        Azure_PCI_DSS_321_Encryption_3 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when \'Enforce SSL connection\' is set to \'ENABLED\' for PostgreSQL Database Server', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Enabled')
      await testRule(data, Result.PASS)
    })

    test('Security Security Issue when \'Enforce SSL connection\' for PostgreSQL Database Server is not configured', async () => {
      const data: PCIQueryResponse = getTestRuleFixture()
      await testRule(data, Result.FAIL)
    })

    
  })

  describe('Encryption Check 4: Storage Accounts \'Secure transfer required\' should be enabled', () => {
    const getTestRuleFixture = (
      enableHttpsTrafficOnly: string
    ): PCIQueryResponse => {
      return {
        queryazureStorageAccount: [
          {
            id: cuid(),
            enableHttpsTrafficOnly
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
        Azure_PCI_DSS_321_Encryption_4 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Storage Accounts has "Secure transfer required" set to "Enabled"', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Yes')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Storage Accounts has "Secure transfer required" set to "Disabled"', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('No')

      await testRule(data, Result.FAIL)
    })
  })
})
