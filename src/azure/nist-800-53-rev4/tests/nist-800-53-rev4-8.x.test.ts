import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Azure_NIST_800_53_81 from '../rules/azure-nist-800-53-rev4-8.1'

export interface Permission {
  actions: string[]
}
export interface QueryazureAuthRoleDefinition {
  id: string
  assignableScopes: string[]
  permissions: Permission[]
}

export interface NIST8xQueryResponse {
  queryazureAuthRoleDefinition?: QueryazureAuthRoleDefinition[]
}

describe('Azure NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'NIST')
  })

  describe('Azure NIST 8.1 Active Directory custom subscription owner roles should not be created', () => {
    const getTestRuleFixture = (
      assignableScopes: string[],
      actions: string[]
    ): NIST8xQueryResponse => {
      return {
        queryazureAuthRoleDefinition: [
          {
            id: cuid(),
            assignableScopes,
            permissions: [
              {
                actions,
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: NIST8xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_81 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ssignableScope is equal to "/" and not actions set to "*"', async () => {
      const data: NIST8xQueryResponse = getTestRuleFixture(
        ['/'],
        [
          'Microsoft.Insights/components/purge/action',
          'Microsoft.OperationalInsights/workspaces/*/read',
        ]
      )

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when ssignableScope have subscriptions and not actions set to "*"', async () => {
      const data: NIST8xQueryResponse = getTestRuleFixture(
        ['/subscriptions/123456'],
        [
          'Microsoft.Insights/components/purge/action',
          'Microsoft.OperationalInsights/workspaces/*/read',
        ]
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when ssignableScope is equal to "/" and actions set to "*"', async () => {
      const data: NIST8xQueryResponse = getTestRuleFixture(['/'], ['*'])

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when ssignableScope have subscriptions and actions set to "*"', async () => {
      const data: NIST8xQueryResponse = getTestRuleFixture(
        ['/subscriptions/123456'],
        ['*']
      )

      await testRule(data, Result.FAIL)
    })
  })
})
