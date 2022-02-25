/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_CIS_131_31 from '../rules/azure-cis-1.3.1-3.1'
import Azure_CIS_131_35 from '../rules/azure-cis-1.3.1-3.5'
import Azure_CIS_131_36 from '../rules/azure-cis-1.3.1-3.6'
import Azure_CIS_131_38 from '../rules/azure-cis-1.3.1-3.8'
import Azure_CIS_131_39 from '../rules/azure-cis-1.3.1-3.9'

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
}

export interface CIS3xQueryResponse {
  queryazureStorageAccount?: QueryazureStorageAccount[]
}

describe('CIS Microsoft Azure Foundations: 1.3.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine('azure', 'CIS')
  })

  describe('Azure CIS 3.1 Ensure that "Secure transfer required" is set to "Enabled"', () => {
    const getTestRuleFixture = (
      enableHttpsTrafficOnly: string
    ): CIS3xQueryResponse => {
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
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_31 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Storage Accounts has "Secure transfer required" set to "Enabled"', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('Yes')

      await testRule(data, Result.PASS)
    })

    
    test('Security Issue when Storage Accounts has "Secure transfer required" set to "Disabled"', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('No')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 3.5 Ensure that "Public access level" is set to Private for blob containers', () => {
    const getTestRuleFixture = (
      allowBlobPublicAccess: string
    ): CIS3xQueryResponse => {
      return {
        queryazureStorageAccount: [
          {
            id: cuid(),
            allowBlobPublicAccess
          },
        ],
      }
    }

    const testRule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_35 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when blob containers not allow public access', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('No')

      await testRule(data, Result.PASS)
    })

    
    test('Security Issue when blob containers allow public access', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('Yes')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 3.6 Ensure default network access rule for Storage Accounts is set to deny', () => {
    const getTestRuleFixture = (
      networkRuleSetDefaultAction: string
    ): CIS3xQueryResponse => {
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
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_36 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when default network access rule for Storage Accounts is set to "Deny"', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('Deny')

      await testRule(data, Result.PASS)
    })

    
    test('Security Issue when default network access rule for Storage Accounts is set to "Allow"', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('Allow')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 3.8 Ensure soft delete is enabled for Azure Storage', () => {
    const getTestRuleFixture = (
      deleteRetentionPolicyEnabled: boolean,
      deleteRetentionPolicyDays: number | null
    ): CIS3xQueryResponse => {
      return {
        queryazureStorageAccount: [
          {
            id: cuid(),
            blobServiceProperties: {
              deleteRetentionPolicyEnabled,
              deleteRetentionPolicyDays
            }
          },
        ],
      }
    }

    const testRule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_38 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Storage Accounts has set soft delete enabled and days', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(true, 7)

      await testRule(data, Result.PASS)
    })

    
    test('Security Issue when Storage Accounts has set soft delete disabled', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(false, null)

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when Storage Accounts has set soft delete enabled and days are not set', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(true, null)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 3.9 Ensure storage for critical data are encrypted with Customer Managed Key', () => {
    const getTestRuleFixture = (
      encryptionKeySource: string
    ): CIS3xQueryResponse => {
      return {
        queryazureStorageAccount: [
          {
            id: cuid(),
            encryptionKeySource
          },
        ],
      }
    }

    const testRule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_39 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Storage Accounts for critical data are encrypted with Customer Managed Key', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('Microsoft.Keyvault')

      await testRule(data, Result.PASS)
    })

    
    test('Security Issue when Storage Accounts for critical data are encrypted with Microsoft Managed Key', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('Microsoft.Storage')

      await testRule(data, Result.FAIL)
    })
  })
})