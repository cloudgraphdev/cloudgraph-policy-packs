/* eslint-disable max-len */
import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_CIS_131_152 from '../rules/azure-cis-1.3.1-5.1.2'
import Azure_CIS_131_153 from '../rules/azure-cis-1.3.1-5.1.3'
import Azure_CIS_131_154 from '../rules/azure-cis-1.3.1-5.1.4'
import { initRuleEngine, testRule } from './utils'

export interface QueryazureStorageAccountData {
  encryptionKeySource: string
  storageContainers: Array<{
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
      ...(encryptionKeySource
        ? {
            storageAccount: {
              encryptionKeySource,
              storageContainers,
            },
          }
        : {}),
    })
  }
  if (queryType === 'queryazureDiagnosticSetting') {
    result.queryazureDiagnosticSetting.push({
      id: cuid(),
      appropiateCategories,
      logs,
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
})
