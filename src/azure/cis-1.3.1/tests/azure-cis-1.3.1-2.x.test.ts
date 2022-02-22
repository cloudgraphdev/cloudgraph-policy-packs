/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_CIS_131_21 from '../rules/azure-cis-1.3.1-2.1'
import Azure_CIS_131_22 from '../rules/azure-cis-1.3.1-2.2'
import Azure_CIS_131_23 from '../rules/azure-cis-1.3.1-2.3'
import Azure_CIS_131_24 from '../rules/azure-cis-1.3.1-2.4'
import Azure_CIS_131_25 from '../rules/azure-cis-1.3.1-2.5'
import Azure_CIS_131_26 from '../rules/azure-cis-1.3.1-2.6'
import Azure_CIS_131_27 from '../rules/azure-cis-1.3.1-2.7'
import Azure_CIS_131_28 from '../rules/azure-cis-1.3.1-2.8'

export interface QueryazureSecurityPricing {
  id: string
  name: string | null
  pricingTier: string | null
}

export interface CIS1xQueryResponse {
  queryazureSecurityPricing?: QueryazureSecurityPricing[]
}

describe('CIS Microsoft Azure Foundations: 1.3.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine('azure', 'CIS')
  })

  describe('Azure CIS 2.1 Ensure that Azure Defender is set to On for Servers', () => {
    const getTestRuleFixture = (
      name: string | null,
      pricingTier: string | null
    ): CIS1xQueryResponse => {
      return {
        queryazureSecurityPricing: [
          {
            id: cuid(),
            name,
            pricingTier
          },
        ],
      }
    }

    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_21 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Azure Defender plan is set to "VirtualMachines" and "Standard" pricing tier', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('VirtualMachines', 'Standard')

      await testRule(data, Result.PASS)
    })

    
    test('Security Issue when Azure Defender plan is not activated for "VirtualMachines"', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('VirtualMachines', null)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 2.2 Ensure that Azure Defender is set to On for App Service', () => {
    const getTestRuleFixture = (
      name: string | null,
      pricingTier: string | null
    ): CIS1xQueryResponse => {
      return {
        queryazureSecurityPricing: [
          {
            id: cuid(),
            name,
            pricingTier
          },
        ],
      }
    }

    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_22 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Azure Defender plan is set to "AppServices" and "Standard" pricing tier', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('AppServices', 'Standard')

      await testRule(data, Result.PASS)
    })

    
    test('Security Issue when Azure Defender plan is not activated for "AppServices"', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('AppServices', null)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 2.3 Ensure that Azure Defender is set to On for Azure SQL database servers', () => {
    const getTestRuleFixture = (
      name: string | null,
      pricingTier: string | null
    ): CIS1xQueryResponse => {
      return {
        queryazureSecurityPricing: [
          {
            id: cuid(),
            name,
            pricingTier
          },
        ],
      }
    }

    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_23 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Azure Defender plan is set to "SqlServers" and "Standard" pricing tier', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('SqlServers', 'Standard')

      await testRule(data, Result.PASS)
    })

    
    test('Security Issue when Azure Defender plan is not activated for "SqlServers"', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('SqlServers', null)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 2.4 Ensure that Azure Defender is set to On for SQL servers on machines', () => {
    const getTestRuleFixture = (
      name: string | null,
      pricingTier: string | null
    ): CIS1xQueryResponse => {
      return {
        queryazureSecurityPricing: [
          {
            id: cuid(),
            name,
            pricingTier
          },
        ],
      }
    }

    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_24 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Azure Defender plan is set to "SqlserverVirtualMachines" and "Standard" pricing tier', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('SqlserverVirtualMachines', 'Standard')

      await testRule(data, Result.PASS)
    })

    
    test('Security Issue when Azure Defender plan is not activated for "SqlserverVirtualMachines"', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('SqlserverVirtualMachines', null)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 2.5 Ensure that Azure Defender is set to On for Storage', () => {
    const getTestRuleFixture = (
      name: string | null,
      pricingTier: string | null
    ): CIS1xQueryResponse => {
      return {
        queryazureSecurityPricing: [
          {
            id: cuid(),
            name,
            pricingTier
          },
        ],
      }
    }

    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_25 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Azure Defender plan is set to "StorageAccounts" and "Standard" pricing tier', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('StorageAccounts', 'Standard')

      await testRule(data, Result.PASS)
    })

    
    test('Security Issue when Azure Defender plan is not activated for "StorageAccounts"', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('StorageAccounts', null)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 2.6 Ensure that Azure Defender is set to On for Kubernetes', () => {
    const getTestRuleFixture = (
      name: string | null,
      pricingTier: string | null
    ): CIS1xQueryResponse => {
      return {
        queryazureSecurityPricing: [
          {
            id: cuid(),
            name,
            pricingTier
          },
        ],
      }
    }

    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_26 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Azure Defender plan is set to "KubernetesService" and "Standard" pricing tier', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('KubernetesService', 'Standard')

      await testRule(data, Result.PASS)
    })

    
    test('Security Issue when Azure Defender plan is not activated for "KubernetesService"', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('KubernetesService', null)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 2.7 Ensure that Azure Defender is set to On for Container Registries', () => {
    const getTestRuleFixture = (
      name: string | null,
      pricingTier: string | null
    ): CIS1xQueryResponse => {
      return {
        queryazureSecurityPricing: [
          {
            id: cuid(),
            name,
            pricingTier
          },
        ],
      }
    }

    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_27 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Azure Defender plan is set to "ContainerRegistry" and "Standard" pricing tier', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('ContainerRegistry', 'Standard')

      await testRule(data, Result.PASS)
    })

    
    test('Security Issue when Azure Defender plan is not activated for "ContainerRegistry"', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('ContainerRegistry', null)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 2.8 Ensure that Azure Defender is set to On for Key Vault', () => {
    const getTestRuleFixture = (
      name: string | null,
      pricingTier: string | null
    ): CIS1xQueryResponse => {
      return {
        queryazureSecurityPricing: [
          {
            id: cuid(),
            name,
            pricingTier
          },
        ],
      }
    }

    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_28 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Azure Defender plan is set to "KeyVaults" and "Standard" pricing tier', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('KeyVaults', 'Standard')

      await testRule(data, Result.PASS)
    })

    
    test('Security Issue when Azure Defender plan is not activated for "KeyVaults"', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('KeyVaults', null)

      await testRule(data, Result.FAIL)
    })
  })
})
