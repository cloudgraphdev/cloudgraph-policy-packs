/* eslint-disable max-len */
import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_NIST_800_53_31 from '../rules/azure-nist-800-53-rev4-3.1'
import Azure_NIST_800_53_32 from '../rules/azure-nist-800-53-rev4-3.2'
import Azure_NIST_800_53_33 from '../rules/azure-nist-800-53-rev4-3.3'
import Azure_NIST_800_53_34 from '../rules/azure-nist-800-53-rev4-3.4'
import Azure_NIST_800_53_35 from '../rules/azure-nist-800-53-rev4-3.5'
import Azure_NIST_800_53_36 from '../rules/azure-nist-800-53-rev4-3.6'
import { initRuleEngine, testRule } from './utils'

export interface azureActivityLogAlertAllOfCondition {
  allOf: [azureActivityLogAlertLeafCondition]
}

export interface azureActivityLogAlertLeafCondition {
  id: string
  field: string
  equals: string
}
export interface azureActivityLogAlertAllOfCondition {
  allOf: [azureActivityLogAlertLeafCondition]
}
export interface QueryazureActivityLogAlert {
  id: string
  region?: string
  enabled?: boolean
  condition?: azureActivityLogAlertAllOfCondition
}

export interface QueryazureResourceGroup {
  id: string
  activityLogAlerts: QueryazureActivityLogAlert[]
}

export interface NIST3xQueryResponse {
  queryazureActivityLogAlert?: QueryazureActivityLogAlert[]
  queryazureResourceGroup?: QueryazureResourceGroup[]
}
export interface QueryazureStorageAccountData {
  encryptionKeySource?: string
  storageContainers?: Array<{
    name: string
  }>
}

export interface QueryazureStorageContainer {
  id: string
  name: string
  publicAccess?: string
  storageAccount?: QueryazureStorageAccountData
}
export interface QueryazureDiagnosticSettingLog {
  category: string
  enabled: boolean
  retentionPolicyEnabled: boolean
  retentionPolicyDays: number | null
}

export interface QueryazureDiagnosticSetting {
  id: string
  appropiateCategories?: boolean
  logs?: QueryazureDiagnosticSettingLog[]
  storageAccount?: QueryazureStorageAccountData
}

export interface FirewallRules {
  startIpAddress: string | undefined
  endIpAddress: string | undefined
}

export interface QueryazureSqlServer {
  id: string
  firewallRules?: FirewallRules[]
}

export interface NIST3xQueryResponse {
  queryazureStorageContainer?: QueryazureStorageContainer[]
  queryazureDiagnosticSetting?: QueryazureDiagnosticSetting[]
  queryazureSqlServer?: QueryazureSqlServer[]
}

type NIST3xQueryType =
  | 'queryazureStorageContainer'
  | 'queryazureDiagnosticSetting'

const getTestRuleFixture = ({
  queryType,
  name = 'whatever',
  encryptionKeySource,
  publicAccess,
  appropiateCategories,
  storageContainers = [],
  logs = [],
}: {
  queryType?: NIST3xQueryType
  name?: string
  encryptionKeySource?: string
  publicAccess?: string
  appropiateCategories?: boolean
  storageContainers?: Array<{
    name: string
  }>
  logs?: QueryazureDiagnosticSettingLog[]
}): NIST3xQueryResponse => {
  const result: NIST3xQueryResponse = {}
  result.queryazureDiagnosticSetting = []
  result.queryazureStorageContainer = []
  if (queryType === 'queryazureStorageContainer') {
    result.queryazureStorageContainer.push({
      id: cuid(),
      name,
      publicAccess,
      storageAccount: {
        encryptionKeySource,
        storageContainers,
      },
    })
  }
  if (queryType === 'queryazureDiagnosticSetting') {
    result.queryazureDiagnosticSetting.push({
      id: cuid(),
      appropiateCategories,
      logs,
      storageAccount: {
        encryptionKeySource,
        storageContainers,
      },
    })
  }
  return result
}

describe('Azure NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'NIST')
  })

  describe('Azure NIST 3.1 Monitor Activity Log Alert should exist for Create or Update Network Security Group', () => {
    const getTestRuleFixture_525 = (
      region: string,
      enabled: boolean,
      field: string,
      equals: string
    ): NIST3xQueryResponse => {
      return {
        queryazureResourceGroup: [
          {
            id: cuid(),
            activityLogAlerts: [
              {
                id: cuid(),
                region,
                enabled,
                condition: {
                  allOf: [
                    {
                      id: cuid(),
                      field,
                      equals,
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    test('No Security Issue when Activity Log Alert exists for Create or Update Network Security Group Rule', async () => {
      const data: NIST3xQueryResponse = getTestRuleFixture_525(
        'global',
        true,
        'operationName',
        'microsoft.network/networksecuritygroups/securityrules/write'
      )

      await testRule(rulesEngine, data, Azure_NIST_800_53_31 as Rule, Result.PASS)
    })

    test('Security Issue when Activity Log Alert doesnt exist for Create or Update Network Security Group Rule', async () => {
      const data: NIST3xQueryResponse = getTestRuleFixture_525(
        'global',
        true,
        '',
        ''
      )

      await testRule(rulesEngine, data, Azure_NIST_800_53_31 as Rule, Result.FAIL)
    })
  })

  describe('Azure NIST 3.2 Monitor Activity Log Alert should exist for Create or Update Network Security Group Rule', () => {
    const getTestRuleFixture = (
      region: string,
      enabled: boolean,
      field: string,
      equals: string,
    ): NIST3xQueryResponse => {
      return {
        queryazureResourceGroup: [
          {
            id: cuid(),
            activityLogAlerts: [{
              id: cuid(),
              region,
              enabled,
              condition: {
                allOf: [{
                  id: cuid(),
                  field,
                  equals,
                }]
              },
            }],
          },
        ],
      }
    }

    const testRule = async (
      data: NIST3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_32 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Create or Update or Delete SQL Server Firewall Rule', async () => {
      const data: NIST3xQueryResponse = getTestRuleFixture('global', true, 'operationName', 'microsoft.sql/servers/firewallrules/write')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Activity Log Alert doesnt exist for Create or Update or Delete SQL Server Firewall Rule', async () => {
      const data: NIST3xQueryResponse = getTestRuleFixture('global', true, '', '')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 3.3 Monitor Activity Log Alert should exist for Create or Update or Delete SQL Server Firewall Rule', () => {
    const getTestRuleFixture = (
      region: string,
      enabled: boolean,
      field: string,
      equals: string,
    ): NIST3xQueryResponse => {
      return {
        queryazureResourceGroup: [
          {
            id: cuid(),
            activityLogAlerts: [{
              id: cuid(),
              region,
              enabled,
              condition: {
                allOf: [{
                  id: cuid(),
                  field,
                  equals,
                }]
              },
            }],
          },
        ],
      }
    }

    const testRule = async (
      data: NIST3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_33 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Create or Update or Delete SQL Server Firewall Rule', async () => {
      const data: NIST3xQueryResponse = getTestRuleFixture('global', true, 'operationName', 'microsoft.sql/servers/firewallrules/write')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Activity Log Alert doesnt exist for Create or Update or Delete SQL Server Firewall Rule', async () => {
      const data: NIST3xQueryResponse = getTestRuleFixture('global', true, '', '')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 3.4 Monitor Activity Log Alert should exist for Delete Network Security Group', () => {
    const getTestRuleFixture_524 = (
      region: string,
      enabled: boolean,
      field: string,
      equals: string
    ): NIST3xQueryResponse => {
      return {
        queryazureResourceGroup: [
          {
            id: cuid(),
            activityLogAlerts: [
              {
                id: cuid(),
                region,
                enabled,
                condition: {
                  allOf: [
                    {
                      id: cuid(),
                      field,
                      equals,
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    test('No Security Issue when Activity Log Alert exists for Delete Network Security Group', async () => {
      const data: NIST3xQueryResponse = getTestRuleFixture_524(
        'global',
        true,
        'operationName',
        'microsoft.network/networksecuritygroups/delete'
      )

      await testRule(rulesEngine, data, Azure_NIST_800_53_34 as Rule, Result.PASS)
    })

    test('Security Issue when Activity Log Alert doesnt exist for Delete Network Security Group', async () => {
      const data: NIST3xQueryResponse = getTestRuleFixture_524(
        'global',
        true,
        '',
        ''
      )

      await testRule(rulesEngine, data, Azure_NIST_800_53_34 as Rule, Result.FAIL)
    })
  })

  describe('Azure NIST 3.5 Monitor Activity Log Alert should exist for Delete Network Security Group Rule', () => {
    const getTestRuleFixture_526 = (
      region: string,
      enabled: boolean,
      field: string,
      equals: string
    ): NIST3xQueryResponse => {
      return {
        queryazureResourceGroup: [
          {
            id: cuid(),
            activityLogAlerts: [
              {
                id: cuid(),
                region,
                enabled,
                condition: {
                  allOf: [
                    {
                      id: cuid(),
                      field,
                      equals,
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    test('No Security Issue when Activity Log Alert exists for the Delete Network Security Group Rule', async () => {
      const data: NIST3xQueryResponse = getTestRuleFixture_526(
        'global',
        true,
        'operationName',
        'microsoft.network/networksecuritygroups/securityrules/delete'
      )

      await testRule(rulesEngine, data, Azure_NIST_800_53_35 as Rule, Result.PASS)
    })

    test('Security Issue when Activity Log Alert doesnt exist for the Delete Network Security Group Rule', async () => {
      const data: NIST3xQueryResponse = getTestRuleFixture_526(
        'global',
        true,
        '',
        ''
      )

      await testRule(rulesEngine, data, Azure_NIST_800_53_35 as Rule, Result.FAIL)
    })
  })

  describe('Azure NIST 3.6 Virtual Network Network Watcher should be enabled', () => {
    const getTestRuleFixture = (
      startIpAddress?: string,
      endIpAddress?: string
    ): NIST3xQueryResponse => {
      return {
        queryazureSqlServer: [
          {
            id: cuid(),
            firewallRules: [
              {
                startIpAddress,
                endIpAddress
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: NIST3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_36 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when no SQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: NIST3xQueryResponse = getTestRuleFixture('127.0.0.0', '127.255.255.255')

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when there no are any firewall configured', async () => {
      const data: NIST3xQueryResponse = getTestRuleFixture()
      const sqlServer = data.queryazureSqlServer?.[0] as QueryazureSqlServer
      sqlServer.firewallRules = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when SQL Databases allow ingress 0.0.0.0/0 (ANY IP)', async () => {
      const data: NIST3xQueryResponse = getTestRuleFixture('0.0.0.0', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when SQL Databases allow ingress 255.255.255.255/0 (ANY IP)', async () => {
      const data: NIST3xQueryResponse = getTestRuleFixture('255.255.255.255', '0.0.0.0')

      await testRule(data, Result.FAIL)
    })
  })
})
