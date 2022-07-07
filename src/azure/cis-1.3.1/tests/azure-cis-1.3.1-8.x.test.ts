/* eslint-disable max-len */
import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_CIS_131_81 from '../rules/azure-cis-1.3.1-8.1'
import Azure_CIS_131_82 from '../rules/azure-cis-1.3.1-8.2'
import Azure_CIS_131_84 from '../rules/azure-cis-1.3.1-8.4'
import Azure_CIS_131_85 from '../rules/azure-cis-1.3.1-8.5'
import { initRuleEngine } from '../../../utils/test'

export interface Attributes {
  enabled: boolean
  expires: string | null
}

export interface Keys {
  attributes: Attributes
}

export interface Properties {
  attributes: Attributes
}

export interface Secrets {
  properties: Properties
}

export interface QueryazureKeyVault {
  id: string
  keys?: Keys[]
  secrets?: Secrets[]
  enableSoftDelete?: boolean | null
  enablePurgeProtection?: boolean | null
  enableRbac?: boolean | null
}

export interface QueryazureAksManagedCluster {
  id: string
  enableRbac?: boolean | null
}
export interface CIS8xQueryResponse {
  queryazureKeyVault?: QueryazureKeyVault[]
  queryazureAksManagedCluster?: QueryazureAksManagedCluster[]
}

describe('CIS Microsoft Azure Foundations: 1.3.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'CIS')
  })

  describe('Azure CIS 8.1 Ensure that the expiration date is set on all keys', () => {
    const getTestRuleFixture = (
      enabled: boolean,
      expires: string | null
    ): CIS8xQueryResponse => {
      return {
        queryazureKeyVault: [
          {
            id: cuid(),
            keys: [
              {
                attributes: {
                  enabled,
                  expires
                }
              }
            ]
          },
        ],
      }
    }

    const testRule = async (
      data: CIS8xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_81 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when the key status is Enabled and expiration date is set on all keys', async () => {
      const data: CIS8xQueryResponse = getTestRuleFixture(true, '2024-02-25T14:18:29.000Z')

      await testRule(data, Result.PASS)
    })

    
    test('Security Issue when the key status is Not Enabled and expiration date is not set on all keys', async () => {
      const data: CIS8xQueryResponse = getTestRuleFixture(false, null)

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when the key status is Enabled but expiration date is not set on all keys', async () => {
      const data: CIS8xQueryResponse = getTestRuleFixture(true, null)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 8.2 Ensure that the expiration date is set on all Secrets', () => {
    const getTestRuleFixture = (
      enabled: boolean,
      expires: string | null
    ): CIS8xQueryResponse => {
      return {
        queryazureKeyVault: [
          {
            id: cuid(),
            secrets: [
              {
                properties: {
                  attributes: {
                    enabled,
                    expires
                  }
                }
              }
            ]
          },
        ],
      }
    }

    const testRule = async (
      data: CIS8xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_82 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when the secret status is Enabled and expiration date is set on all secrets', async () => {
      const data: CIS8xQueryResponse = getTestRuleFixture(true, '2024-02-25T14:18:29.000Z')

      await testRule(data, Result.PASS)
    })

    
    test('Security Issue when the secret status is Not Enabled and expiration date is not set on all secrets', async () => {
      const data: CIS8xQueryResponse = getTestRuleFixture(false, null)

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when the secret status is Enabled but expiration date is not set on all secrets', async () => {
      const data: CIS8xQueryResponse = getTestRuleFixture(true, null)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 8.4 Ensure the key vault is recoverable', () => {
    const getTestRuleFixture = (
      enableSoftDelete: boolean | null,
      enablePurgeProtection: boolean | null
    ): CIS8xQueryResponse => {
      return {
        queryazureKeyVault: [
          {
            id: cuid(),
            enableSoftDelete,
            enablePurgeProtection
          },
        ],
      }
    }

    const testRule = async (
      data: CIS8xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_84 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when enableSoftDelete and enablePurgeProtection are set to enabled', async () => {
      const data: CIS8xQueryResponse = getTestRuleFixture(true, true)

      await testRule(data, Result.PASS)
    })
  
    test('Security Issue when enableSoftDelete and enablePurgeProtection are disabled', async () => {
      const data: CIS8xQueryResponse = getTestRuleFixture(false, false)

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when enableSoftDelete is enabled but enablePurgeProtection is not set', async () => {
      const data: CIS8xQueryResponse = getTestRuleFixture(true, null)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 8.5 Enable role-based access control (RBAC) within Azure Kubernetes Services', () => {
    const getTestRuleFixture = (
      enableRbac: boolean | null,
    ): CIS8xQueryResponse => {
      return {
        queryazureAksManagedCluster: [
          {
            id: cuid(),
            enableRbac
          },
        ],
      }
    }

    const testRule = async (
      data: CIS8xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_85 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when role-based access control (RBAC) is enabled', async () => {
      const data: CIS8xQueryResponse = getTestRuleFixture(true)

      await testRule(data, Result.PASS)
    })
  
    test('Security Issue when role-based access control (RBAC) is disabled', async () => {
      const data: CIS8xQueryResponse = getTestRuleFixture(false)

      await testRule(data, Result.FAIL)
    })
  })
})