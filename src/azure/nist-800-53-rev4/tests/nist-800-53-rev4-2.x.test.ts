import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Azure_NIST_800_53_21 from '../rules/azure-nist-800-53-rev4-2.1'
import Azure_NIST_800_53_22 from '../rules/azure-nist-800-53-rev4-2.2'
import Azure_NIST_800_53_23 from '../rules/azure-nist-800-53-rev4-2.3'
import Azure_NIST_800_53_24 from '../rules/azure-nist-800-53-rev4-2.4'
import Azure_NIST_800_53_25 from '../rules/azure-nist-800-53-rev4-2.5'

export interface Log {
  category: string
  retentionPolicyEnabled: boolean
  retentionPolicyDays: number
}

export interface DiagnosticSetting {
  logs: Log[]
}

export interface RetentionPolicy {
  enabled: boolean
  days: number
}

export interface ServerBlobAuditingPolicy {
  state: string
}

export interface QueryazureSqlServer {
  id: string
  serverBlobAuditingPolicies: ServerBlobAuditingPolicy[]
}

export interface QueryazureKeyVault {
  id: string
  diagnosticSettings: DiagnosticSetting[]
}

export interface QueryazureLogProfile {
  id: string
  name?: string
  locations?: string[]
  categories?: string[]
  retentionPolicy?: RetentionPolicy | null
}

export interface NIST2xQueryResponse {
  queryazureLogProfile?: QueryazureLogProfile[]
  queryazureKeyVault?: QueryazureKeyVault[]
  queryazureSqlServer?: QueryazureSqlServer[]
}

describe('Azure NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'NIST')
  })

  describe('Azure NIST 2.1 Monitor audit profile should log all activities', () => {
    const getTestRuleFixture = (categories: string[]): NIST2xQueryResponse => {
      return {
        queryazureLogProfile: [
          {
            id: cuid(),
            categories,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST2xQueryResponse,
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
      const data: NIST2xQueryResponse = getTestRuleFixture([
        'Action',
        'Write',
        'Delete',
      ])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when Monitor audit profile not log all activities', async () => {
      const data: NIST2xQueryResponse = getTestRuleFixture(['Action', 'Delete'])
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when Monitor audit profile log activities are empty', async () => {
      const data: NIST2xQueryResponse = getTestRuleFixture([])
      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 2.2 Key Vault logging should be enabled', () => {
    const getTestRuleFixture = (
      category: string,
      retentionPolicyEnabled: boolean,
      retentionPolicyDays: number
    ): NIST2xQueryResponse => {
      return {
        queryazureKeyVault: [
          {
            id: cuid(),
            diagnosticSettings: [
              {
                logs: [
                  {
                    category,
                    retentionPolicyEnabled,
                    retentionPolicyDays,
                  },
                ],
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_22 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Key Vault logging is enabled', async () => {
      const data: NIST2xQueryResponse = getTestRuleFixture(
        'AuditEvent',
        true,
        180
      )
      await testRule(data, Result.PASS)
    })

    test('Security Issue when Key Vault logging is not enabled', async () => {
      const data: NIST2xQueryResponse = getTestRuleFixture(
        'AuditEvent',
        false,
        180
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when Key Vault logging retentionPolicyDays is less than 180', async () => {
      const data: NIST2xQueryResponse = getTestRuleFixture(
        'AuditEvent',
        true,
        179
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when Key Vault logging is empty', async () => {
      const data: NIST2xQueryResponse = getTestRuleFixture('', false, 0)
      const keyVaults = data.queryazureKeyVault?.[0] as QueryazureKeyVault
      keyVaults.diagnosticSettings = []
      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 2.3 Monitor log profile should be created', () => {
    const getTestRuleFixture = (
      enabled: boolean,
      days: number
    ): NIST2xQueryResponse => {
      return {
        queryazureLogProfile: [
          {
            id: cuid(),
            retentionPolicy: {
              enabled,
              days,
            },
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_23 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Monitor audit profile log is created', async () => {
      const data: NIST2xQueryResponse = getTestRuleFixture(true, 0)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when Monitor audit profile log is not created', async () => {
      const data: NIST2xQueryResponse = getTestRuleFixture(false, 0)
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when Monitor audit profile log is empty', async () => {
      const data: NIST2xQueryResponse = getTestRuleFixture(false, 0)
      const logProfile = data.queryazureLogProfile?.[0] as QueryazureLogProfile
      logProfile.retentionPolicy = null
      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 2.4 Monitor log profile should have activity logs for global services and all regions', () => {
    const getTestRuleFixture = (
      name: string,
      locations: string[]
    ): NIST2xQueryResponse => {
      return {
        queryazureLogProfile: [
          {
            id: cuid(),
            name,
            locations
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_24 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Monitor log profile have activity logs for global services and all regions', async () => {
      const data: NIST2xQueryResponse = getTestRuleFixture('default',  [
        'centralus',
        'eastus',
        'northcentralus',
        'southcentralus',
        'westus',
        'francecentral',
        'germanynorth',
        'swedencentral',
        'global',
      ])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when Monitor log profile have activity logs for global services but not for all regions', async () => {
      const data: NIST2xQueryResponse = getTestRuleFixture('default',  [
        'centralus',
        'eastus',
        'northcentralus',
        'southcentralus',
      ])
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when Monitor log profile not have activity logs for global services and all regions', async () => {
      const data: NIST2xQueryResponse = getTestRuleFixture('test',  [
        'centralus',
        'eastus',
        'northcentralus',
        'southcentralus',
        'westus',
        'francecentral',
        'germanynorth',
        'swedencentral',
        'global',
      ])
      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 2.5 SQL Server auditing should be enabled', () => {
    const getTestRuleFixture = (
      state: string
      ): NIST2xQueryResponse => {
      return {
        queryazureSqlServer: [
          {
            id: cuid(),
            serverBlobAuditingPolicies: [
              {
                state
              }
            ]
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_25 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when SQL Server auditing is enabled', async () => {
      const data: NIST2xQueryResponse = getTestRuleFixture('Enabled')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when SQL Server auditing is disabled', async () => {
      const data: NIST2xQueryResponse = getTestRuleFixture('Disabled')
      await testRule(data, Result.FAIL)
    })
  })
})
