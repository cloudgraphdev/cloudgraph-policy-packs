import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_PCI_DSS_321_Storage_1 from '../rules/pci-dss-3.2.1-storage-check-1'
import Gcp_PCI_DSS_321_Storage_2 from '../rules/pci-dss-3.2.1-storage-check-2'

export interface DatabaseFlagsItem {
  name: string
  value: string | null
}

export interface AuthorizedNetwork {
  value: string
}

export interface IpConfiguration {
  requireSsl?: boolean | null
  authorizedNetworks?: AuthorizedNetwork[]
}

export interface BackupConfiguration {
  enabled: boolean | null
  startTime: string | null
}

export interface Settings {
  databaseFlags: DatabaseFlagsItem[]
  ipConfiguration?: IpConfiguration
  backupConfiguration?: BackupConfiguration
}

export interface IpAddress {
  type: string
}

export interface SqlInstances {
  id?: string
  name: string
  settings: Settings
  ipAddresses?: IpAddress[]
}

export interface CISStorageQueryResponse {
  querygcpSqlInstance?: SqlInstances[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'PCI'} )
  })

  describe('Storage Check 1: Ensure that Cloud SQL database instances are not open to the world', () => {
    const getRulesStorage1Fixture = (): CISStorageQueryResponse => {
      return {
        querygcpSqlInstance: [
          {
            id: cuid(),
            name: 'test-sql-instance',
            settings: {
              ipConfiguration: {
                authorizedNetworks: [
                  { value: '192.168.0.0/24' },
                  { value: '192.168.1.0/24' },
                ],
              },
              databaseFlags: [],
            },
          },
        ],
      }
    }

    const testStorage1Rule = async (
      data: CISStorageQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_Storage_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when authorizedNetworks is NOT set to '0.0.0.0/0'", async () => {
      const data: CISStorageQueryResponse = getRulesStorage1Fixture()
      await testStorage1Rule(data, Result.PASS)
    })

    test('No Security Issue when authorizedNetworks is empty', async () => {
      const data: CISStorageQueryResponse = getRulesStorage1Fixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      sqlInstance.settings = {
        ipConfiguration: {
          authorizedNetworks: [],
        },
        databaseFlags: [],
      }
      await testStorage1Rule(data, Result.PASS)
    })

    test("Security Issue when authorizedNetworks is set to '0.0.0.0/0'", async () => {
      const data: CISStorageQueryResponse = getRulesStorage1Fixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      sqlInstance.settings = {
        ipConfiguration: {
          authorizedNetworks: [{ value: '0.0.0.0/0' }],
        },
        databaseFlags: [],
      }
      await testStorage1Rule(data, Result.FAIL)
    })
  })

  describe('Storage Check 2: Ensure that the Cloud SQL database instance requires all incoming connections to use SSL', () => {
    const getRulesStorage2Fixture = (): CISStorageQueryResponse => {
      return {
        querygcpSqlInstance: [
          {
            id: cuid(),
            name: 'test-sql-instance',
            settings: {
              ipConfiguration: {
                requireSsl: true,
              },
              databaseFlags: [],
            },
          },
        ],
      }
    }

    const testStorage2Rule = async (
      data: CISStorageQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_Storage_2 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when requireSsl is set to true', async () => {
      const data: CISStorageQueryResponse = getRulesStorage2Fixture()
      await testStorage2Rule(data, Result.PASS)
    })

    test('Security Issue when requireSsl is set to false', async () => {
      const data: CISStorageQueryResponse = getRulesStorage2Fixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      const ipConfiguration = sqlInstance.settings
        .ipConfiguration as IpConfiguration
      ipConfiguration.requireSsl = false
      await testStorage2Rule(data, Result.FAIL)
    })

    test('Security Issue when requireSsl is set to null', async () => {
      const data: CISStorageQueryResponse = getRulesStorage2Fixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      const ipConfiguration = sqlInstance.settings
        .ipConfiguration as IpConfiguration
      ipConfiguration.requireSsl = null
      await testStorage2Rule(data, Result.FAIL)
    })
  })
  
})
