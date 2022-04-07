/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_CIS_131_72 from '../rules/azure-cis-1.3.1-7.2'
import Azure_CIS_131_73 from '../rules/azure-cis-1.3.1-7.3'

export interface QueryazureDisk {
  id: string
  diskState?: string
  encryptionSettings?: string
}

export interface CIS7xQueryResponse {
  queryazureDisk?: QueryazureDisk[]
}

describe('CIS Microsoft Azure Foundations: 1.3.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'azure',
      entityName: 'CIS',
    })
  })

  describe('Azure CIS 7.2 Ensure that "OS and Data" disks are encrypted with CMK', () => {
    const getTestRuleFixture = (
      encryptionSettings: string
    ): CIS7xQueryResponse => {
      return {
        queryazureDisk: [
          {
            id: cuid(),
            encryptionSettings,
          },
        ],
      }
    }

    const testRule = async (
      data: CIS7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_72 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when OS disk and Data disks have encryption set to CMK', async () => {
      const data: CIS7xQueryResponse = getTestRuleFixture(
        'EncryptionAtRestWithCustomerKey'
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when OS disk or Data disks have no encryption set to CMK', async () => {
      const data: CIS7xQueryResponse = getTestRuleFixture(
        'EncryptionAtRestWithPlatformKey'
      )

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 7.3 Ensure that "Unattached disks" are encrypted with CMK', () => {
    const getTestRuleFixture = (
      diskState: string,
      encryptionSettings: string
    ): CIS7xQueryResponse => {
      return {
        queryazureDisk: [
          {
            id: cuid(),
            diskState,
            encryptionSettings,
          },
        ],
      }
    }

    const testRule = async (
      data: CIS7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_73 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when "Unattached disks" are encrypted with CMK', async () => {
      const data: CIS7xQueryResponse = getTestRuleFixture(
        'Unattached',
        'EncryptionAtRestWithCustomerKey'
      )

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when is not an "Unattached disks"', async () => {
      const data: CIS7xQueryResponse = getTestRuleFixture(
        'Attached',
        'EncryptionAtRestWithPlatformKey'
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when "Unattached disks" are not encrypted with CMK', async () => {
      const data: CIS7xQueryResponse = getTestRuleFixture(
        'Unattached',
        'EncryptionAtRestWithPlatformKey'
      )

      await testRule(data, Result.FAIL)
    })
  })
})
