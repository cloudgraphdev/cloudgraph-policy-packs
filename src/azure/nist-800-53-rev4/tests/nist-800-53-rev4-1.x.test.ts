import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Azure_NIST_800_53_11 from '../rules/azure-nist-800-53-rev4-1.1'
import Azure_NIST_800_53_12 from '../rules/azure-nist-800-53-rev4-1.2'

export interface Disk {
  osType: string | null
  azureDiskEncryptionEnabled: boolean
}

export interface QueryazureVirtualMachine {
  id: string
  disks: Disk[]
}

export interface QueryazureDisk {
  id: string
  diskState: string
  azureDiskEncryptionEnabled: boolean
}

export interface NIS1xQueryResponse {
  queryazureDisk?: QueryazureDisk[]
  queryazureVirtualMachine?: QueryazureVirtualMachine[]
}

describe('Azure NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'azure',
      entityName: 'NIST',
    })
  })

  describe('Azure NIST 1.1 Virtual Machines unattached disks should be encrypted', () => {
    const getTestRuleFixture = (
      diskState: string,
      azureDiskEncryptionEnabled: boolean
      ): NIS1xQueryResponse => {
      return {
        queryazureDisk: [
          {
            id: cuid(),
            diskState,
            azureDiskEncryptionEnabled
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_11 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when unattached disks are encrypted', async () => {
      const data: NIS1xQueryResponse = getTestRuleFixture('Unattached', true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when unattached disks are not encrypted', async () => {
      const data: NIS1xQueryResponse = getTestRuleFixture('Unattached', false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 1.2 Virtual Machines data disks (non-boot volumes) should be encrypted', () => {
    const getTestRuleFixture = (
      osType: string | null,
      azureDiskEncryptionEnabled: boolean
      ): NIS1xQueryResponse => {
      return {
        queryazureVirtualMachine: [
          {
            id: cuid(),
            disks: [
              {
                osType,
                azureDiskEncryptionEnabled
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_12 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Virtual Machines data disks are encrypted', async () => {
      const data: NIS1xQueryResponse = getTestRuleFixture(null, true)
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when Virtual Machines are not data disks type', async () => {
      const data: NIS1xQueryResponse = getTestRuleFixture('linux', false)
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when Virtual Machines data disks are not encrypted', async () => {
      const data: NIS1xQueryResponse = getTestRuleFixture(null, false)
      await testRule(data, Result.FAIL)
    })
  })

})
