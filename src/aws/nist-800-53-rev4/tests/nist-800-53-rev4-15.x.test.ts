import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_NIST_800_53_151 from '../rules/aws-nist-800-53-rev4-15.1'
import Aws_NIST_800_53_152 from '../rules/aws-nist-800-53-rev4-15.2'

export interface ContainerDefinition {
  user: string
}

export interface Condition {
  key: string
  value: string[]
}

export interface Statement {
  condition: Condition[]
}

export interface AssumeRolePolicy {
  statement: Statement[]
}

export interface QueryawsIamRole {
  id: string
  assumeRolePolicy: AssumeRolePolicy
}

export interface QueryawsEcsTaskDefinition {
  id: string
  containerDefinitions?: ContainerDefinition[]
}

export interface NIS15xQueryResponse {
  queryawsEcsTaskDefinition?: QueryawsEcsTaskDefinition[]
  queryawsIamRole?: QueryawsIamRole[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'NIST',
    })
  })

  describe('AWS NIST 15.1 ECS task definitions should not use the root user', () => {
    const getTestRuleFixture = (user: string): NIS15xQueryResponse => {
      return {
        queryawsEcsTaskDefinition: [
          {
            id: cuid(),
            containerDefinitions: [
              {
                user
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS15xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_151 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when task definitions not use the root user', async () => {
      const data: NIS15xQueryResponse = getTestRuleFixture('testuser')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when task definitions use the root user', async () => {
      const data: NIS15xQueryResponse = getTestRuleFixture('root')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 15.2 IAM roles used for trust relationships should have MFA or external IDs', () => {
    const getTestRuleFixture = (
      condition: Condition[]
      ): NIS15xQueryResponse => {
      return {
        queryawsIamRole: [
          {
            id: cuid(),
            assumeRolePolicy: {
              statement: [
                {
                  condition
                }
              ]
            }
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS15xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_152 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when IAM roles used for trust relationships have external IDs', async () => {
      const condition: Condition[] =  [{key: 'sts:ExternalId', value: [cuid()]}]
      const data: NIS15xQueryResponse = getTestRuleFixture(condition)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when IAM roles used for trust relationships NOT have external IDs', async () => {
      const condition: Condition[] = []
      const data: NIS15xQueryResponse = getTestRuleFixture(condition)
      await testRule(data, Result.FAIL)
    })
  })
})