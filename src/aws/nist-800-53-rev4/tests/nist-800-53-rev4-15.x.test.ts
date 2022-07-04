import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_NIST_800_53_151 from '../rules/aws-nist-800-53-rev4-15.1'
import Aws_NIST_800_53_152 from '../rules/aws-nist-800-53-rev4-15.2'
import Aws_NIST_800_53_153 from '../rules/aws-nist-800-53-rev4-15.3'
import Aws_NIST_800_53_154 from '../rules/aws-nist-800-53-rev4-15.4'

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
export interface QueryawsIamUser {
  id: string
  name?: string
  accessKeysActive?: boolean
  passwordLastUsed?: string
  passwordEnabled?: boolean
}
export interface NIST15xQueryResponse {
  queryawsEcsTaskDefinition?: QueryawsEcsTaskDefinition[]
  queryawsIamRole?: QueryawsIamRole[]
  queryawsIamUser?: QueryawsIamUser[]
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
    const getTestRuleFixture = (user: string): NIST15xQueryResponse => {
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
      data: NIST15xQueryResponse,
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
      const data: NIST15xQueryResponse = getTestRuleFixture('testuser')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when task definitions use the root user', async () => {
      const data: NIST15xQueryResponse = getTestRuleFixture('root')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 15.2 IAM roles used for trust relationships should have MFA or external IDs', () => {
    const getTestRuleFixture = (
      condition: Condition[]
      ): NIST15xQueryResponse => {
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
      data: NIST15xQueryResponse,
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
      const data: NIST15xQueryResponse = getTestRuleFixture(condition)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when IAM roles used for trust relationships NOT have external IDs', async () => {
      const condition: Condition[] = []
      const data: NIST15xQueryResponse = getTestRuleFixture(condition)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 15.3 IAM root user access key should not exist', () => {
    const getTestRuleFixture = (
      accessKeysActive: boolean
    ): NIST15xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            accessKeysActive,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: NIST15xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_153 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there is an inbound rule with a root account that does not have any access key active', async () => {
      const data: NIST15xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a root account that has at least one access key active', async () => {
      const data: NIST15xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 15.4 IAM root user should not be used', () => {
    const getTestRuleFixture = (
      passwordEnabled: boolean,
      passwordLastUsed: string,
    ): NIST15xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            passwordLastUsed,
            passwordEnabled,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: NIST15xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_154 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there is an inbound rule with a root account that does not uses his password in the last 30 days', async () => {
      const data: NIST15xQueryResponse = getTestRuleFixture(true, '2021-04-08T17:20:19.000Z')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a root account that uses his password in the last 30 days', async () => {
      const data: NIST15xQueryResponse = getTestRuleFixture(true, new Date().toISOString())
      await testRule(data, Result.FAIL)
    })
  })
})