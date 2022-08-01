import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Azure_NIST_800_53_71 from '../rules/azure-nist-800-53-rev4-7.1'

export interface Configuration {
  name: string
  value: string
}

export interface QueryazurePostgreSqlServer {
  id: string
  configurations: Configuration[]
}

export interface NIST8xQueryResponse {
  queryazurePostgreSqlServer?: QueryazurePostgreSqlServer[]
}

describe('Azure NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'NIST')
  })

  describe('Azure NIST 7.1 PostgreSQL Database configuration "connection_throttling" should be on', () => {
    const getTestRuleFixture = (
      name: string,
      value: string
      ): NIST8xQueryResponse => {
      return {
        queryazurePostgreSqlServer: [
          {
            id: cuid(),
            configurations: [
              {
                name,
                value,
              }
            ]
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST8xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_71 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when PostgreSQL Database configuration "connection_throttling" is set to on', async () => {
      const data: NIST8xQueryResponse = getTestRuleFixture('connection_throttling', 'on')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when PostgreSQL Database configuration "connection_throttling" is set to off', async () => {
      const data: NIST8xQueryResponse = getTestRuleFixture('connection_throttling', 'off')
      await testRule(data, Result.FAIL)
    })
  })
})
