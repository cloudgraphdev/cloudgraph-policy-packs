import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Aws_NIST_800_53_111 from '../rules/aws-nist-800-53-rev4-11.1'
import Aws_NIST_800_53_112 from '../rules/aws-nist-800-53-rev4-11.2'

export interface QueryawsEcsTaskDefinition {
  id: string
  memory?: string | null
  cpu?: string | null
}

export interface NIST11xQueryResponse {
  queryawsEcsTaskDefinition?: QueryawsEcsTaskDefinition[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'NIST')
  })

  describe('AWS NIST 11.1 ECS task definitions should limit memory usage for containers', () => {
    const getTestRuleFixture = (
      memory: string | null
    ): NIST11xQueryResponse => {
      return {
        queryawsEcsTaskDefinition: [
          {
            id: cuid(),
            memory,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST11xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_111 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Container memory is within the acceptable limit (512)', async () => {
      const data: NIST11xQueryResponse = getTestRuleFixture('512')
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when Container memory is within the acceptable limit (256)', async () => {
      const data: NIST11xQueryResponse = getTestRuleFixture('256')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when Container memory is not set', async () => {
      const data: NIST11xQueryResponse = getTestRuleFixture(null)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 11.2 ECS task definitions should set CPU limit for containers', () => {
    const getTestRuleFixture = (cpu: string | null): NIST11xQueryResponse => {
      return {
        queryawsEcsTaskDefinition: [
          {
            id: cuid(),
            cpu,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST11xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_112 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when CPU limit is within the acceptable limit (512)', async () => {
      const data: NIST11xQueryResponse = getTestRuleFixture('512')
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when CPU limit is within the acceptable limit (256)', async () => {
      const data: NIST11xQueryResponse = getTestRuleFixture('256')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when CPU limit is not set', async () => {
      const data: NIST11xQueryResponse = getTestRuleFixture(null)
      await testRule(data, Result.FAIL)
    })
  })
})
