import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Azure_PCI_DSS_321_Logging_1 from '../rules/pci-dss-3.2.1-logging-check-1'

export interface RetentionPolicy {
  enabled: boolean
  days: number
}

export interface QueryazureLogProfile {
  id: string
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

  describe('Logging Check 1: Monitor log profile should be created', () => {
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
        Azure_PCI_DSS_321_Logging_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Monitor audit profile log is created', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, 0)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when Monitor audit profile log is not created', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(false, 0)
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when Monitor audit profile log is empty', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(false, 0)
      const logProfile = data.queryazureLogProfile?.[0] as QueryazureLogProfile
      logProfile.retentionPolicy = null
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when Monitor audit profile is not set to retain the events indefinitely', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, 7)
      await testRule(data, Result.FAIL)
    })
  })
})
