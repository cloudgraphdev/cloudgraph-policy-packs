import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_PCI_DSS_321_41 from '../rules/pci-dss-3.2.1-4.1'

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

export interface CIS4xQueryResponse {
  querygcpSqlInstance?: SqlInstances[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'PCI'} )
  })

  describe('GCP PCI 4.1 Ensure that the Cloud SQL database instance requires all incoming connections to use SSL', () => {
    const getRuleFixture = (): CIS4xQueryResponse => {
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

    const test41Rule = async (
      data: CIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_41 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when requireSsl is set to true', async () => {
      const data: CIS4xQueryResponse = getRuleFixture()
      await test41Rule(data, Result.PASS)
    })

    test('Security Issue when requireSsl is set to false', async () => {
      const data: CIS4xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      const ipConfiguration = sqlInstance.settings
        .ipConfiguration as IpConfiguration
      ipConfiguration.requireSsl = false
      await test41Rule(data, Result.FAIL)
    })

    test('Security Issue when requireSsl is set to null', async () => {
      const data: CIS4xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      const ipConfiguration = sqlInstance.settings
        .ipConfiguration as IpConfiguration
      ipConfiguration.requireSsl = null
      await test41Rule(data, Result.FAIL)
    })
  })

})
