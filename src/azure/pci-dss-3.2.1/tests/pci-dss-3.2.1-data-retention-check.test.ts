import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Azure_PCI_DSS_321_Data_Retention_Check_1 from '../rules/pci-dss-3.2.1-data-retention-check-1'

export interface RetentionPolicy {
  enabled: boolean
  days: number
}

export interface QueryazureLogProfile {
  id: string
  name?: string
  locations?: string[]
  categories?: string[]
  retentionPolicy?: RetentionPolicy | null
}

export interface PCIQueryResponse {
  queryazureLogProfile?: QueryazureLogProfile[]
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'PCI')
  })

  describe('Retention Check 1: Activity Log Retention should be 365 days or greater', () => {
    const getTestRuleFixture = (
      enabled: boolean,
      days: number,
    ): PCIQueryResponse => {
      return {
        queryazureLogProfile: [
          {
            id: cuid(),
            retentionPolicy: {
              enabled,
              days,
            },
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Data_Retention_Check_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Monitor audit profile log retention day is 0 means logs are kept forever', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, 0)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when Monitor audit profile log is less than 365 days', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, 364)
      await testRule(data, Result.FAIL)
    })

    test('No Security Issue when Monitor audit profile log retention day is 365 days', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, 365)
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when Monitor audit profile log retention day is more than 365 days', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, 366)
      await testRule(data, Result.PASS)
    })
  })
})
