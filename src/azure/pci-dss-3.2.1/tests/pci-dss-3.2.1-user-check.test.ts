import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Azure_PCI_DSS_321_User_1 from '../rules/pci-dss-3.2.1-user-check-1'

export interface Permission {
  actions: string[]
}
export interface QueryazureAuthRoleDefinition {
  id: string
  assignableScopes: string[]
  permissions: Permission[]
}

export interface PCIQueryResponse {
  queryazureAuthRoleDefinition?: QueryazureAuthRoleDefinition[]
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'PCI')
  })

  describe('Monitoring Check 1: Active Directory custom subscription owner roles should not be created', () => {
    const getTestRuleFixture = (
      assignableScopes: string[],
      actions: string[]
    ): PCIQueryResponse => {
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
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_User_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ssignableScope have subscriptions and not actions set to "*"', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        ['/subscriptions/123456'],
        [
          'Microsoft.Insights/components/purge/action',
          'Microsoft.OperationalInsights/workspaces/*/read',
        ]
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when ssignableScope is equal to "/" and actions set to "*"', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(['/'], ['*'])

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when ssignableScope have subscriptions and actions set to "*"', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        ['/subscriptions/123456'],
        ['*']
      )

      await testRule(data, Result.FAIL)
    })
  });
});
