import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_NIST_800_53_51 from '../rules/aws-nist-800-53-rev4-5.1'

export interface QueryawsRdsDbInstance {
  id: string
  engine: string
}

export interface NIST5xQueryResponse {
  queryawsRdsDbInstance?: QueryawsRdsDbInstance[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'NIST',
    })
  })

  describe('AWS NIST 5.1 RDS instances should have FedRAMP approved database engines', () => {
    const getTestRuleFixture = (
      engine: string
    ): NIST5xQueryResponse => {
      return {
        queryawsRdsDbInstance: [
          {
            id: cuid(),
            engine
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_51 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when RDS instances have FedRAMP approved database engines', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('mysql')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when RDS instances not have FedRAMP approved database engines', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('mongoDb')
      await testRule(data, Result.FAIL)
    })
  })
})
