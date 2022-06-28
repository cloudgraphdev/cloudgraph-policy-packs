import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Azure_NIST_800_53_21 from '../rules/azure-nist-800-53-rev4-2.1'

export interface QueryazureLogProfile {
  id: string
  categories: string[]
}

export interface NIS2xQueryResponse {
  queryazureLogProfile?: QueryazureLogProfile[]
}

describe('Azure NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'azure',
      entityName: 'NIST',
    })
  })

  describe('Azure NIST 2.1 Monitor audit profile should log all activities', () => {
    const getTestRuleFixture = (
      categories: string[]
      ): NIS2xQueryResponse => {
      return {
        queryazureLogProfile: [
          {
            id: cuid(),
            categories
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_21 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Monitor audit profile log all activities', async () => {
      const data: NIS2xQueryResponse = getTestRuleFixture(['Action', 'Write', 'Delete'])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when Monitor audit profile not log all activities', async () => {
      const data: NIS2xQueryResponse = getTestRuleFixture(['Action', 'Delete'])
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when Monitor audit profile log activities are empty', async () => {
      const data: NIS2xQueryResponse = getTestRuleFixture([])
      await testRule(data, Result.FAIL)
    })
  })
})
