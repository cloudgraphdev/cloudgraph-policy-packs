/* eslint-disable max-len */
import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_CIS_131_13 from '../rules/azure-cis-1.3.1-1.3'
import Azure_CIS_131_121 from '../rules/azure-cis-1.3.1-1.21'
import Azure_CIS_131_122 from '../rules/azure-cis-1.3.1-1.22'
import { initRuleEngine } from '../../../utils/test'

export interface Permission {
  actions: string[]
}
export interface QueryazureAuthRoleDefinition {
  id: string
  assignableScopes: string[]
  permissions: Permission[]
}

export interface QueryazureADUser {
  id: string
  userType: string
  accountEnabled?: boolean
  createdDateTime: string
}

export interface QueryazureAdIdentitySecurityDefaultsEnforcementPolicy {
  id: string
  isEnabled: boolean
}

export interface CIS1xQueryResponse {
  queryazureADUser?: QueryazureADUser[]
  queryazureAuthRoleDefinition?: QueryazureAuthRoleDefinition[]
  queryazureAdIdentitySecurityDefaultsEnforcementPolicy?: QueryazureAdIdentitySecurityDefaultsEnforcementPolicy[]
}

describe('CIS Microsoft Azure Foundations: 1.3.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'CIS')
  })

  describe('Azure CIS 1.3 Ensure guest users are reviewed on a monthly basis', () => {
    const getTestRuleFixture = (
      accountEnabled: boolean,
      createdDateTime: string
    ): CIS1xQueryResponse => {
      return {
        queryazureADUser: [
          {
            id: cuid(),
            userType: 'Guest',
            accountEnabled,
            createdDateTime
          },
        ],
      }
    }

    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_13 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Guest users have account enabled and cretedDateTime within the last 30 days', async () => {
      const createdDateTime = new Date()
      createdDateTime.setDate(createdDateTime.getDate() - 30);
      const data: CIS1xQueryResponse = getTestRuleFixture(true, createdDateTime.toISOString())

      await testRule(data, Result.PASS)
    })

    test('Security Issue when Guest users have the account not enabled', async () => {
      const createdDateTime = new Date()
      createdDateTime.setDate(createdDateTime.getDate() - 30);
      const data: CIS1xQueryResponse = getTestRuleFixture(false, createdDateTime.toISOString())

      await testRule(data, Result.FAIL)
    })

    test('Security issue when Guest users have account with createdDateTime greater than 30 days', async () => {
      const createdDateTime = new Date()
      createdDateTime.setDate(createdDateTime.getDate() - 40);
      const data: CIS1xQueryResponse = getTestRuleFixture(true, createdDateTime.toISOString())

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 1.21 Ensure that no custom subscription owner roles are created', () => {
    const getTestRuleFixture = (
      assignableScopes: string[],
      actions: string[]
    ): CIS1xQueryResponse => {
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
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_121 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ssignableScope is equal to "/" and not actions set to "*"', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(
        ['/'],
        [
          'Microsoft.Insights/components/purge/action',
          'Microsoft.OperationalInsights/workspaces/*/read',
        ]
      )

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when ssignableScope have subscriptions and not actions set to "*"', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(
        ['/subscriptions/123456'],
        [
          'Microsoft.Insights/components/purge/action',
          'Microsoft.OperationalInsights/workspaces/*/read',
        ]
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when ssignableScope is equal to "/" and actions set to "*"', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(['/'], ['*'])

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when ssignableScope have subscriptions and actions set to "*"', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(
        ['/subscriptions/123456'],
        ['*']
      )

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 1.22 Ensure Security Defaults is enabled on Azure Active Directory', () => {
    const getTestRuleFixture = (isEnabled: boolean): CIS1xQueryResponse => {
      return {
        queryazureAdIdentitySecurityDefaultsEnforcementPolicy: [
          {
            id: cuid(),
            isEnabled,
          },
        ],
      }
    }

    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_122 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Security Defaults is enabled on Azure Active Directory', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(true)

      await testRule(data, Result.PASS)
    })

    test('Security Issue when Security Defaults is not enabled on Azure Active Directory', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(false)

      await testRule(data, Result.FAIL)
    })
  })
})
