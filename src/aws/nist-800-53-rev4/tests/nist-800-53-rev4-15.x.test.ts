import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_NIST_800_53_153 from '../rules/aws-nist-800-53-rev4-15.3'
import Aws_NIST_800_53_154 from '../rules/aws-nist-800-53-rev4-15.4'

export interface QueryawsIamUser {
  id: string
  accessKeysActive?: boolean
  passwordLastUsed?: string
  passwordEnabled?: boolean
}

export interface NIST13xQueryResponse {
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

  describe('AWS NIST 15.3 IAM root user access key should not exist', () => {
    const getTestRuleFixture = (
      accessKeysActive: boolean
    ): NIST13xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            accessKeysActive,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: NIST13xQueryResponse,
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
      const data: NIST13xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a root account that has at least one access key active', async () => {
      const data: NIST13xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 15.4 IAM root user should not be used', () => {
    const getTestRuleFixture = (
      passwordEnabled: boolean,
      passwordLastUsed: string,
    ): NIST13xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            passwordLastUsed,
            passwordEnabled,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: NIST13xQueryResponse,
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
      const data: NIST13xQueryResponse = getTestRuleFixture(true, '2021-04-08T17:20:19.000Z')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a root account that uses his password in the last 30 days', async () => {
      const data: NIST13xQueryResponse = getTestRuleFixture(true, new Date().toISOString())
      await testRule(data, Result.FAIL)
    })
  })
})