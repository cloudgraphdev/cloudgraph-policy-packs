/* eslint-disable max-len */
import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_CIS_131_152 from '../rules/azure-cis-1.3.1-5.1.2'
import Azure_CIS_131_153 from '../rules/azure-cis-1.3.1-5.1.3'
import Azure_CIS_131_154 from '../rules/azure-cis-1.3.1-5.1.4'
import Azure_CIS_131_521 from '../rules/azure-cis-1.3.1-5.2.1'
import Azure_CIS_131_522 from '../rules/azure-cis-1.3.1-5.2.2'
import Azure_CIS_131_523 from '../rules/azure-cis-1.3.1-5.2.3'
import Azure_CIS_131_524 from '../rules/azure-cis-1.3.1-5.2.4'
import Azure_CIS_131_525 from '../rules/azure-cis-1.3.1-5.2.5'
import Azure_CIS_131_526 from '../rules/azure-cis-1.3.1-5.2.6'
import Azure_CIS_131_527 from '../rules/azure-cis-1.3.1-5.2.7'
import Azure_CIS_131_528 from '../rules/azure-cis-1.3.1-5.2.8'
import Azure_CIS_131_529 from '../rules/azure-cis-1.3.1-5.2.9'
import { initRuleEngine, testRule } from '../../../utils/test'

export interface azureActivityLogAlertLeafCondition {
  id: string
  field: string
  equals: string
}
export interface azureActivityLogAlertAllOfCondition {
  allOf: [azureActivityLogAlertLeafCondition]
}
export interface ActivityLogAlert {
  id: string
  enabled?: boolean
  condition?: azureActivityLogAlertAllOfCondition
}

export interface QueryazureSubscription {
  id: string
  activityLogAlerts: ActivityLogAlert[]
}

export interface CIS5xQueryResponse {
  queryazureSubscription?: QueryazureSubscription[]
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

export interface CIS51xQueryResponse {
  queryazureStorageContainer?: QueryazureStorageContainer[]
  queryazureDiagnosticSetting?: QueryazureDiagnosticSetting[]
}

type CIS51xQueryType =
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
  queryType?: CIS51xQueryType
  name?: string
  encryptionKeySource?: string
  publicAccess?: string
  appropiateCategories?: boolean
  storageContainers?: Array<{
    name: string
  }>
  logs?: QueryazureDiagnosticSettingLog[]
}): CIS51xQueryResponse => {
  const result: CIS51xQueryResponse = {}
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

describe('CIS Microsoft Azure Foundations: 1.3.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'CIS')
  })

  describe('Azure 5.1.2 Ensure Diagnostic Setting captures appropriate categories', () => {
    test('Checks any if insights-activity-logs is found and has the appropiate categories set', async () => {
      const data: CIS51xQueryResponse = getTestRuleFixture({
        queryType: 'queryazureDiagnosticSetting',
        name: 'insights-activity-logs',
        appropiateCategories: true,
        storageContainers: [{ name: 'insights-activity-logs' }],
      })
      await testRule(rulesEngine, data, Azure_CIS_131_152 as Rule, Result.PASS)
    })

    test('Checks any if insights-activity-logs is found and but does not have the appropiate categories set', async () => {
      const data: CIS51xQueryResponse = getTestRuleFixture({
        queryType: 'queryazureDiagnosticSetting',
        name: 'insights-activity-logs',
        appropiateCategories: false,
        storageContainers: [{ name: 'insights-activity-logs' }],
      })
      await testRule(rulesEngine, data, Azure_CIS_131_152 as Rule, Result.FAIL)
    })

    test('No settings found', async () => {
      const data: CIS51xQueryResponse = getTestRuleFixture({
        queryType: 'queryazureDiagnosticSetting',
        appropiateCategories: false,
      })
      await testRule(rulesEngine, data, Azure_CIS_131_152 as Rule, Result.FAIL)
    })
  })

  describe('Azure 5.1.3 Ensure the storage container storing the activity logs is not publicly accessible', () => {
    test('Finds insights-operational-logs storage container and checks that publicAccess prop equals "None"', async () => {
      const data: CIS51xQueryResponse = getTestRuleFixture({
        queryType: 'queryazureStorageContainer',
        name: 'insights-operational-logs',
        publicAccess: 'None',
      })
      await testRule(rulesEngine, data, Azure_CIS_131_153 as Rule, Result.PASS)
    })

    test('Finds insights-operational-logs storage container and fails checks because publicAccess is set to "Storage', async () => {
      const data: CIS51xQueryResponse = getTestRuleFixture({
        queryType: 'queryazureStorageContainer',
        name: 'insights-operational-logs',
        publicAccess: 'Storage',
      })
      await testRule(rulesEngine, data, Azure_CIS_131_153 as Rule, Result.FAIL)
    })

    test('Container not found', async () => {
      const data: CIS51xQueryResponse = getTestRuleFixture({
        queryType: 'queryazureStorageContainer',
        name: 'scm-releases',
        publicAccess: 'Storage',
      })
      await testRule(rulesEngine, data, Azure_CIS_131_153 as Rule, Result.FAIL)
    })
  })

  describe('Azure 5.1.4 Ensure the storage account containing the container with activity logs is encrypted with BYOK (Use Your Own Key)', () => {
    test('Finds insights-operational-logs storage container and storage account is encrypted with BYOK', async () => {
      const data: CIS51xQueryResponse = getTestRuleFixture({
        queryType: 'queryazureStorageContainer',
        name: 'insights-operational-logs',
        encryptionKeySource: 'Microsoft.Keyvault',
      })
      await testRule(rulesEngine, data, Azure_CIS_131_154 as Rule, Result.PASS)
    })

    test('Finds insights-operational-logs storage container and storage account is encrypted by system managed key(Storage)', async () => {
      const data: CIS51xQueryResponse = getTestRuleFixture({
        queryType: 'queryazureStorageContainer',
        name: 'insights-operational-logs',
        encryptionKeySource: 'Microsoft.Storage',
      })
      await testRule(rulesEngine, data, Azure_CIS_131_154 as Rule, Result.FAIL)
    })

    test('Container not found', async () => {
      const data: CIS51xQueryResponse = getTestRuleFixture({
        queryType: 'queryazureStorageContainer',
        name: 'scm-releases',
        encryptionKeySource: 'Microsoft.Storage',
      })
      await testRule(rulesEngine, data, Azure_CIS_131_154 as Rule, Result.FAIL)
    })
  })
  describe('Azure CIS 5.2.1 Ensure that Activity Log Alert exists for Create Policy Assignment', () => {
    const getTestRuleFixture_521 = (
      enabled: boolean,
      field: string,
      equals: string
    ): CIS5xQueryResponse => {
      return {
        queryazureSubscription: [
          {
            id: cuid(),
            activityLogAlerts: [
              {
                id: cuid(),
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

    test('No Security Issue when Activity Log Alert exists for Create Policy Assignment', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture_521(
        true,
        'operationName',
        'microsoft.authorization/policyassignments/write'
      )

      await testRule(rulesEngine, data, Azure_CIS_131_521 as Rule, Result.PASS)
    })

    test('Security Issue when Activity Log Alert doesnt exist for Create Policy Assignment', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture_521(
        true,
        '',
        ''
      )

      await testRule(rulesEngine, data, Azure_CIS_131_521 as Rule, Result.FAIL)
    })
  })

  describe('Azure CIS 5.2.2 Ensure that Activity Log Alert exists for Delete Policy Assignment', () => {
    const getTestRuleFixture_522 = (
      enabled: boolean,
      field: string,
      equals: string
    ): CIS5xQueryResponse => {
      return {
        queryazureSubscription: [
          {
            id: cuid(),
            activityLogAlerts: [
              {
                id: cuid(),
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

    test('No Security Issue when Activity Log Alert exists for Delete Policy Assignment', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture_522(
        true,
        'operationName',
        'microsoft.authorization/policyassignments/delete'
      )

      await testRule(rulesEngine, data, Azure_CIS_131_522 as Rule, Result.PASS)
    })

    test('Security Issue when Activity Log Alert doesnt exist for Delete Policy Assignment', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture_522(
        true,
        '',
        ''
      )

      await testRule(rulesEngine, data, Azure_CIS_131_522 as Rule, Result.FAIL)
    })
  })

  describe('Azure CIS 5.2.3 Ensure that Activity Log Alert exists for Create or Update Network Security Group', () => {
    const getTestRuleFixture_523 = (
      enabled: boolean,
      field: string,
      equals: string
    ): CIS5xQueryResponse => {
      return {
        queryazureSubscription: [
          {
            id: cuid(),
            activityLogAlerts: [
              {
                id: cuid(),
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

    test('No Security Issue when Activity Log Alert exists for Create or Update Network Security Group', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture_523(
        true,
        'operationName',
        'microsoft.network/networksecuritygroups/write'
      )

      await testRule(rulesEngine, data, Azure_CIS_131_523 as Rule, Result.PASS)
    })

    test('Security Issue when Activity Log Alert doesnt exist for Create or Update Network Security Group', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture_523(
        true,
        '',
        ''
      )

      await testRule(rulesEngine, data, Azure_CIS_131_523 as Rule, Result.FAIL)
    })
  })

  describe('Azure CIS 5.2.4 Ensure that Activity Log Alert exists for Delete Network Security Group', () => {
    const getTestRuleFixture_524 = (
      enabled: boolean,
      field: string,
      equals: string
    ): CIS5xQueryResponse => {
      return {
        queryazureSubscription: [
          {
            id: cuid(),
            activityLogAlerts: [
              {
                id: cuid(),
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
      const data: CIS5xQueryResponse = getTestRuleFixture_524(
        true,
        'operationName',
        'microsoft.network/networksecuritygroups/delete'
      )

      await testRule(rulesEngine, data, Azure_CIS_131_524 as Rule, Result.PASS)
    })

    test('Security Issue when Activity Log Alert doesnt exist for Delete Network Security Group', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture_524(
        true,
        '',
        ''
      )

      await testRule(rulesEngine, data, Azure_CIS_131_524 as Rule, Result.FAIL)
    })
  })

  describe('Azure CIS 5.2.5 Ensure that Activity Log Alert exists for Create or Update Network Security Group Rule', () => {
    const getTestRuleFixture_525 = (
      enabled: boolean,
      field: string,
      equals: string
    ): CIS5xQueryResponse => {
      return {
        queryazureSubscription: [
          {
            id: cuid(),
            activityLogAlerts: [
              {
                id: cuid(),
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
      const data: CIS5xQueryResponse = getTestRuleFixture_525(
        true,
        'operationName',
        'microsoft.network/networksecuritygroups/securityrules/write'
      )

      await testRule(rulesEngine, data, Azure_CIS_131_525 as Rule, Result.PASS)
    })

    test('Security Issue when Activity Log Alert doesnt exist for Create or Update Network Security Group Rule', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture_525(
        true,
        '',
        ''
      )

      await testRule(rulesEngine, data, Azure_CIS_131_525 as Rule, Result.FAIL)
    })
  })

  describe('Azure CIS 5.2.6 Ensure that Activity Log Alert exists for the Delete Network Security Group Rule', () => {
    const getTestRuleFixture_526 = (
      enabled: boolean,
      field: string,
      equals: string
    ): CIS5xQueryResponse => {
      return {
        queryazureSubscription: [
          {
            id: cuid(),
            activityLogAlerts: [
              {
                id: cuid(),
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
      const data: CIS5xQueryResponse = getTestRuleFixture_526(
        true,
        'operationName',
        'microsoft.network/networksecuritygroups/securityrules/delete'
      )

      await testRule(rulesEngine, data, Azure_CIS_131_526 as Rule, Result.PASS)
    })

    test('Security Issue when Activity Log Alert doesnt exist for the Delete Network Security Group Rule', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture_526(
        true,
        '',
        ''
      )

      await testRule(rulesEngine, data, Azure_CIS_131_526 as Rule, Result.FAIL)
    })
  })

  describe('Azure CIS 5.2.7 Ensure that Activity Log Alert exists for Create or Update Security Solution', () => {
    const getTestRuleFixture = (
      enabled: boolean,
      field: string,
      equals: string,
    ): CIS5xQueryResponse => {
      return {
        queryazureSubscription: [
          {
            id: cuid(),
            activityLogAlerts: [{
              id: cuid(),
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
      data: CIS5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_527 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Create or Update Security Solution', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture(true, 'operationName', 'microsoft.security/securitysolutions/write')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Activity Log Alert doesnt exist for Create or Update Security Solution', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture(true, '', '')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 5.2.8 Ensure that Activity Log Alert exists for Delete Security Solution', () => {
    const getTestRuleFixture = (
      enabled: boolean,
      field: string,
      equals: string,
    ): CIS5xQueryResponse => {
      return {
        queryazureSubscription: [
          {
            id: cuid(),
            activityLogAlerts: [{
              id: cuid(),
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
      data: CIS5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_528 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Delete Security Solution', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture(true, 'operationName', 'microsoft.security/securitysolutions/delete')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Activity Log Alert doesnt exist for Delete Security Solution', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture(true, '', '')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 5.2.9 Ensure that Activity Log Alert exists for Create or Update or Delete SQL Server Firewall Rule', () => {
    const getTestRuleFixture = (
      enabled: boolean,
      field: string,
      equals: string,
    ): CIS5xQueryResponse => {
      return {
        queryazureSubscription: [
          {
            id: cuid(),
            activityLogAlerts: [{
              id: cuid(),
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
      data: CIS5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_529 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Create or Update or Delete SQL Server Firewall Rule', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture(true, 'operationName', 'microsoft.sql/servers/firewallrules/write')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Activity Log Alert doesnt exist for Create or Update or Delete SQL Server Firewall Rule', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture(true, '', '')

      await testRule(data, Result.FAIL)
    })
  })
})
