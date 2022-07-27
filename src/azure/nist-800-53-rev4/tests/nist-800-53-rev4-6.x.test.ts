
import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_NIST_800_53_61 from '../rules/azure-nist-800-53-rev4-6.1'
import Azure_NIST_800_53_62 from '../rules/azure-nist-800-53-rev4-6.2'
import Azure_NIST_800_53_63 from '../rules/azure-nist-800-53-rev4-6.3'
import Azure_NIST_800_53_64 from '../rules/azure-nist-800-53-rev4-6.4'
import { initRuleEngine } from '../../../utils/test'

export interface QueryazurePostgreSqlServer {
  id: string
  sslEnforcement?: string
}

export interface QueryazureMySqlServer {
  id: string
  sslEnforcement?: string
}

export interface QueryazureStorageAccount {
  id: string
  enableHttpsTrafficOnly?: string
}

export interface QueryazureAppServiceWebApp {
  id: string
  name?: string
  httpsOnly?: boolean
}

export interface NIST6xResponse {
  queryazureStorageAccount?: QueryazureStorageAccount[]
  queryazureAppServiceWebApp?: QueryazureAppServiceWebApp[]
  queryazurePostgreSqlServer?: QueryazurePostgreSqlServer[]
  queryazureMySqlServer?: QueryazureMySqlServer[]
}

describe('Azure NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'NIST')
  })

  describe('Azure NIST 6.1 Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service', () => {
    const getTestRuleFixture = (httpsOnly: boolean): NIST6xResponse => {
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
      data: NIST6xResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_61 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a httpsOnly set to On', async () => {
      const data: NIST6xResponse = getTestRuleFixture(true)

      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a httpsOnly set to Off', async () => {
      const data: NIST6xResponse = getTestRuleFixture(false)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 6.2 Ensure \'Enforce SSL connection\' is set to \'ENABLED\' for MySQL Database Server', () => {
    const getTestRuleFixture = (
      sslEnforcement?: string | undefined
    ): NIST6xResponse => {
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
      data: NIST6xResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_62 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when \'Enforce SSL connection\' is set to \'ENABLED\' for MySQL Database Server', async () => {
      const data: NIST6xResponse = getTestRuleFixture('Enabled')

      await testRule(data, Result.PASS)
    })

    test('Security Security Issue when \'Enforce SSL connection\' for MySQL Database Server is not configured', async () => {
      const data: NIST6xResponse = getTestRuleFixture()

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 6.3 Ensure \'Enforce SSL connection\' is set to \'ENABLED\' for PostgreSQL Database Server', () => {
    const getTestRuleFixture = (
      sslEnforcement?: string | undefined
    ): NIST6xResponse => {
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
      data: NIST6xResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_63 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when \'Enforce SSL connection\' is set to \'ENABLED\' for PostgreSQL Database Server', async () => {
      const data: NIST6xResponse = getTestRuleFixture('Enabled')
      await testRule(data, Result.PASS)
    })

    test('Security Security Issue when \'Enforce SSL connection\' for PostgreSQL Database Server is not configured', async () => {
      const data: NIST6xResponse = getTestRuleFixture()
      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 6.4 Ensure that "Secure transfer required" is set to "Enabled"', () => {
    const getTestRuleFixture = (
      enableHttpsTrafficOnly: string
    ): NIST6xResponse => {
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
      data: NIST6xResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_64 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Storage Accounts has "Secure transfer required" set to "Enabled"', async () => {
      const data: NIST6xResponse = getTestRuleFixture('Yes')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Storage Accounts has "Secure transfer required" set to "Disabled"', async () => {
      const data: NIST6xResponse = getTestRuleFixture('No')

      await testRule(data, Result.FAIL)
    })
  })
})
