import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_NIST_800_53_41 from '../rules/gcp-nist-800-53-rev4-4.1'
import Gcp_NIST_800_53_42 from '../rules/gcp-nist-800-53-rev4-4.2'
import { initRuleEngine } from '../../../utils/test'


export interface ServiceAccount {
  email: string
  scopes?: string[]
}

export interface Label {
  value: string
}

export interface Project {
  id: string
}

export interface MetadataItem {
  key: string
  value: string
}

export interface Metadata {
  items: MetadataItem[]
}

export interface DiskEncryptionKey {
  sha256: string | null
}

export interface Disk {
  diskEncryptionKey: DiskEncryptionKey | null
}

export interface AccessConfigs {
  natIP: string | null
}

export interface NetworkInterfaces {
  accessConfigs: AccessConfigs[]
}

export interface ShieldedInstanceConfig {
  enableIntegrityMonitoring: boolean
  enableVtpm: boolean
}

export interface ConfidentialInstanceConfig {
  enableConfidentialCompute: boolean
}

export interface QuerygcpVmInstance {
  id: string
  name?: string
  shieldedInstanceConfig?: ShieldedInstanceConfig
  confidentialInstanceConfig?: ConfidentialInstanceConfig
  networkInterfaces?: NetworkInterfaces[]
  canIpForward?: boolean
  project?: Project[]
  labels?: Label[]
  metadata?: Metadata
  serviceAccounts?: ServiceAccount[]
  disks?: Disk[]
}

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

export interface QuerygcpSqlInstance {
  id?: string
  name: string
  settings: Settings
  ipAddresses?: IpAddress[]
}

export interface NIST4xQueryResponse {
  querygcpVmInstance?: QuerygcpVmInstance[]
  querygcpSqlInstance?: QuerygcpSqlInstance[]
}

describe('GCP NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('gcp', 'NIST')
  })

  describe('GCP NIST 4.1 Compute instance disks should be encrypted with customer-supplied encryption keys (CSEKs)', () => {
    const getTestRuleFixture = (disk: Disk): NIST4xQueryResponse => {
      return {
        querygcpVmInstance: [
          {
            id: cuid(),
            name: 'dummy-project-name',
            project: [],
            labels: [],
            serviceAccounts: [],
            disks: [disk],
          },
        ],
      }
    }

    const testRule = async (
      data: NIST4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_41 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when disk has a sha256 key', async () => {
      const disk: Disk = {
        diskEncryptionKey: {
          sha256: 'dummy',
        },
      }

      const data: NIST4xQueryResponse = getTestRuleFixture(disk)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when disk diskEncryptionKey is null', async () => {
      const disk: Disk = {
        diskEncryptionKey: null,
      }

      const data: NIST4xQueryResponse = getTestRuleFixture(disk)
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when disk diskEncryptionKey sha256 is null', async () => {
      const disk: Disk = {
        diskEncryptionKey: {
          sha256: null,
        },
      }

      const data: NIST4xQueryResponse = getTestRuleFixture(disk)
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when disk diskEncryptionKey sha256 is empty', async () => {
      const disk: Disk = {
        diskEncryptionKey: {
          sha256: '',
        },
      }

      const data: NIST4xQueryResponse = getTestRuleFixture(disk)
      await testRule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 6.4 Ensure that the Cloud SQL database instance requires all incoming connections to use SSL', () => {
    const getRuleFixture = (): NIST4xQueryResponse => {
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

    const testRule = async (
      data: NIST4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_42 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when requireSsl is set to true', async () => {
      const data: NIST4xQueryResponse = getRuleFixture()
      await testRule(data, Result.PASS)
    })

    test('Security Issue when requireSsl is set to false', async () => {
      const data: NIST4xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as QuerygcpSqlInstance
      const ipConfiguration = sqlInstance.settings
        .ipConfiguration as IpConfiguration
      ipConfiguration.requireSsl = false
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when requireSsl is set to null', async () => {
      const data: NIST4xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as QuerygcpSqlInstance
      const ipConfiguration = sqlInstance.settings
        .ipConfiguration as IpConfiguration
      ipConfiguration.requireSsl = null
      await testRule(data, Result.FAIL)
    })
  })
})
