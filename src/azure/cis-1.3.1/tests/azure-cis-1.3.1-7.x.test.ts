import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'

import Azure_CIS_131_71 from '../rules/azure-cis-1.3.1-7.1'
import Azure_CIS_131_72 from '../rules/azure-cis-1.3.1-7.2'
import Azure_CIS_131_73 from '../rules/azure-cis-1.3.1-7.3'
import Azure_CIS_131_77 from '../rules/azure-cis-1.3.1-7.7'
import { initRuleEngine } from '../../../utils/test'

export interface Disk {
  id: string
}
export interface QueryazureVirtualMachine {
  id: string
  disks?: Disk[]
}
export interface QueryazureDisk {
  id: string
  diskState?: string
  encryptionSettings?: string
  azureDiskEncryptionEnabled?: boolean
}

export interface CIS7xQueryResponse {
  queryazureDisk?: QueryazureDisk[]
  queryazureVirtualMachine?: QueryazureVirtualMachine[]
}

describe('CIS Microsoft Azure Foundations: 1.3.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'CIS')
  })

  describe('Azure CIS 7.1 Ensure Virtual Machines are utilizing Managed Disks', () => {
    const getTestRuleFixture = (
      disks: Disk[]
    ): CIS7xQueryResponse => {
      return {
        queryazureVirtualMachine: [
          {
            id: cuid(),
            disks,
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
        Azure_CIS_131_71 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Virtual Machines are utilizing Managed Disks', async () => {
      const data: CIS7xQueryResponse = getTestRuleFixture([{ id: cuid()}])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when Virtual Machines are not utilizing Managed Disks', async () => {
      const data: CIS7xQueryResponse = getTestRuleFixture([])
      await testRule(data, Result.FAIL)
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

  describe('Azure CIS 7.7 Ensure that VHD\'s are encrypted', () => {
    const getTestRuleFixture = (
      azureDiskEncryptionEnabled: boolean
    ): CIS7xQueryResponse => {
      return {
        queryazureDisk: [
          {
            id: cuid(),
            azureDiskEncryptionEnabled,
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
        Azure_CIS_131_77 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when VHD\'s are encrypted', async () => {
      const data: CIS7xQueryResponse = getTestRuleFixture(true)

      await testRule(data, Result.PASS)
    })

    test('Security Issue when OS disk or Data disks have no encryption set to CMK', async () => {
      const data: CIS7xQueryResponse = getTestRuleFixture(false)

      await testRule(data, Result.FAIL)
    })
  })
})
