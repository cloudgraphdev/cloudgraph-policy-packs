import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_PCI_DSS_321_11 from '../rules/pci-dss-3.2.1-1.1'
import Gcp_PCI_DSS_321_12 from '../rules/pci-dss-3.2.1-1.2'
import Gcp_PCI_DSS_321_13 from '../rules/pci-dss-3.2.1-1.3'

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

export interface SqlInstances {
  id?: string
  name: string
  settings: Settings
  ipAddresses?: IpAddress[]
}

export interface CIS1xQueryResponse {
  querygcpSqlInstance?: SqlInstances[]
  querygcpVmInstance?: QuerygcpVmInstance[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'PCI'} )
  })

  describe('GCP PCI 1.1 Ensure "Block Project-wide SSH keys" is enabled for VM instances', () => {
    const getTest11RuleFixture = (
      name: string,
      projects: Project[],
      labels: Label[],
      serviceAccounts: ServiceAccount[],
      metadataItems: MetadataItem[]
    ): CIS1xQueryResponse => {
      return {
        querygcpVmInstance: [
          {
            id: cuid(),
            name,
            project: projects,
            labels,
            serviceAccounts,
            metadata: {
              items: metadataItems,
            },
          },
        ],
      }
    }

    const test11Rule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_11 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test(`No Security Issue when the vm name starts with "gke-",
    it has a "goog-gke-node" label
    and the service account is the default compute service account
    and it does have the "block-project-ssh-keys" set to true`, async () => {
      const projectId = 123456789
      const name = 'gke-test'
      const projects: Project[] = [{ id: `projects/${projectId}` }]
      const labels: Label[] = [
        {
          value: 'goog-gke-node',
        },
      ]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: `${projectId}-compute@developer.gserviceaccount.com`,
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'block-project-ssh-keys',
          value: 'true',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.PASS)
    })

    test(`No Security Issue when the vm name starts with "gke-",
    it does NOT have a "goog-gke-node" label,
    the service account is NOT the default compute service account,
    and it does have the "block-project-ssh-keys" set to true`, async () => {
      const name = 'gke-test'
      const projects: Project[] = [{ id: 'projects/dummy-id' }]
      const labels: Label[] = []
      const serviceAccounts: ServiceAccount[] = [
        {
          email: 'dummy-compute@test.com',
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'block-project-ssh-keys',
          value: 'true',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.PASS)
    })

    test(`No Security Issue when the vm name does NOT start with "gke-",
    it has a "goog-gke-node" label,
    the service account is NOT the default compute service account
    and it does have the "block-project-ssh-keys" set to true`, async () => {
      const name = 'dummy'
      const projects: Project[] = [{ id: 'projects/dummy-id' }]
      const labels: Label[] = [
        {
          value: 'goog-gke-node',
        },
      ]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: 'dummy-compute@test.com',
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'block-project-ssh-keys',
          value: 'true',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.PASS)
    })

    test(`No Security Issue when the vm name does NOT start with "gke-",
    it does NOT have a "goog-gke-node" label,
    the service account is NOT the default compute service account
    and it does have the "block-project-ssh-keys" set to true`, async () => {
      const name = 'dummy'
      const projects: Project[] = [{ id: 'projects/dummy-id' }]
      const labels: Label[] = [
        {
          value: 'dummy-label',
        },
      ]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: 'dummy-compute@test.com',
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'block-project-ssh-keys',
          value: 'true',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.PASS)
    })

    test(`No Security Issue when the vm name does NOT start with "gke-",
    it does NOT have a "goog-gke-node" label,
    the service account is NOT the default compute service account
    and it not have metadata`, async () => {
      const name = 'dummy'
      const projects: Project[] = [{ id: 'projects/dummy-id' }]
      const labels: Label[] = [
        {
          value: 'dummy-label',
        },
      ]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: 'dummy-compute@test.com',
        },
      ]
      const metadataItems: MetadataItem[] = []
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.PASS)
    })

    test(`Security Issue when the vm name does NOT start with "gke-",
     it does NOT have a "goog-gke-node" label,
     the service account is the default compute service account,
     and it does have the "block-project-ssh-keys" set to true`, async () => {
      const projectId = 123456789
      const name = 'dummy'
      const projects: Project[] = [{ id: `projects/${projectId}` }]
      const labels: Label[] = [
        {
          value: 'dummy-label',
        },
      ]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: `${projectId}-compute@developer.gserviceaccount.com`,
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'block-project-ssh-keys',
          value: 'true',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.FAIL)
    })

    test(`Security Issue when the vm name does start with "gke-",
    it does NOT have a "goog-gke-node" label,
    the service account is the default compute service account,
    and it does have the "block-project-ssh-keys" set to true`, async () => {
      const name = 'gke-test'
      const labels: Label[] = [
        {
          value: 'dummy-label',
        },
      ]
      const projectId = 123456789
      const projects: Project[] = [{ id: `projects/${projectId}` }]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: `${projectId}-compute@developer.gserviceaccount.com`,
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'block-project-ssh-keys',
          value: 'true',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.FAIL)
    })

    test(`Security Issue when the vm name does start with "gke-",
    it does NOT have any label,
    the service account is the default compute service account,
    and it does have the "block-project-ssh-keys" set to true`, async () => {
      const name = 'gke-test'
      const labels: Label[] = []
      const projectId = 123456789
      const projects: Project[] = [{ id: `projects/${projectId}` }]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: `${projectId}-compute@developer.gserviceaccount.com`,
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'block-project-ssh-keys',
          value: 'true',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.FAIL)
    })

    test(`Security Issue when the vm name does NOT start with "gke-",
    it does have a "goog-gke-node" label
    the service account is the default compute service account
    and it does have the "block-project-ssh-keys" set to true`, async () => {
      const name = 'dummy'
      const labels: Label[] = [
        {
          value: 'dummy-label',
        },
        {
          value: 'goog-gke-node',
        },
      ]
      const projectId = 123456789
      const projects: Project[] = [{ id: `projects/${projectId}` }]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: `${projectId}-compute@developer.gserviceaccount.com`,
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'block-project-ssh-keys',
          value: 'true',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.FAIL)
    })

    test(`Security Issue when the vm name does NOT start with "gke-",
     it does NOT have a "goog-gke-node" label,
     the service account is NOT default compute service account,
     and it does have the "block-project-ssh-keys" set to false`, async () => {
      const projectId = 123456789
      const name = 'dummy'
      const projects: Project[] = [{ id: `projects/${projectId}` }]
      const labels: Label[] = [
        {
          value: 'dummy-label',
        },
      ]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: 'dummy@test.com',
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'block-project-ssh-keys',
          value: 'false',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.FAIL)
    })

    test(`Security Issue when the vm name does start with "gke-",
    it does NOT have a "goog-gke-node" label,
    the service account is NOT the default compute service account,
    and it does have the "block-project-ssh-keys" set to false`, async () => {
      const name = 'gke-test'
      const labels: Label[] = [
        {
          value: 'dummy-label',
        },
      ]
      const projectId = 123456789
      const projects: Project[] = [{ id: `projects/${projectId}` }]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: 'dummy@test.com',
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'block-project-ssh-keys',
          value: 'false',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.FAIL)
    })

    test(`Security Issue when the vm name does start with "gke-",
    it does NOT have any label,
    the service account is NOT the default compute service account,
    and it does have the "block-project-ssh-keys" set to false`, async () => {
      const name = 'gke-test'
      const labels: Label[] = []
      const projectId = 123456789
      const projects: Project[] = [{ id: `projects/${projectId}` }]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: 'dummy@test.com',
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'block-project-ssh-keys',
          value: 'false',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.FAIL)
    })

    test(`Security Issue when the vm name does NOT start with "gke-",
    it does have a "goog-gke-node" label
    the service account is NOT the default compute service account
    and it does have the "block-project-ssh-keys" set to false`, async () => {
      const name = 'dummy'
      const labels: Label[] = [
        {
          value: 'dummy-label',
        },
        {
          value: 'goog-gke-node',
        },
      ]
      const projectId = 123456789
      const projects: Project[] = [{ id: `projects/${projectId}` }]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: 'dummy@test.com',
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'block-project-ssh-keys',
          value: 'false',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.FAIL)
    })

    test(`Security Issue when the vm name does NOT start with "gke-",
     it does NOT have a "goog-gke-node" label,
     the service account is NOT default compute service account,
     and the "block-project-ssh-keys" key is not present`, async () => {
      const projectId = 123456789
      const name = 'dummy'
      const projects: Project[] = [{ id: `projects/${projectId}` }]
      const labels: Label[] = [
        {
          value: 'dummy-label',
        },
      ]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: 'dummy@test.com',
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'dummy-ssh-keys',
          value: 'false',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.FAIL)
    })

    test(`Security Issue when the vm name does start with "gke-",
    it does NOT have a "goog-gke-node" label,
    the service account is NOT the default compute service account,
    and the "block-project-ssh-keys" key is not present`, async () => {
      const name = 'gke-test'
      const labels: Label[] = [
        {
          value: 'dummy-label',
        },
      ]
      const projectId = 123456789
      const projects: Project[] = [{ id: `projects/${projectId}` }]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: 'dummy@test.com',
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'dummy-ssh-keys',
          value: 'false',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.FAIL)
    })

    test(`Security Issue when the vm name does start with "gke-",
    it does NOT have any label,
    the service account is NOT the default compute service account,
    and the "block-project-ssh-keys" key is not present`, async () => {
      const name = 'gke-test'
      const labels: Label[] = []
      const projectId = 123456789
      const projects: Project[] = [{ id: `projects/${projectId}` }]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: 'dummy@test.com',
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'dummy-ssh-keys',
          value: 'false',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.FAIL)
    })

    test(`Security Issue when the vm name does NOT start with "gke-",
    it does have a "goog-gke-node" label
    the service account is NOT the default compute service account
    and the "block-project-ssh-keys" key is not present`, async () => {
      const name = 'dummy'
      const labels: Label[] = [
        {
          value: 'dummy-label',
        },
        {
          value: 'goog-gke-node',
        },
      ]
      const projectId = 123456789
      const projects: Project[] = [{ id: `projects/${projectId}` }]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: 'dummy@test.com',
        },
      ]
      const metadataItems: MetadataItem[] = [
        {
          key: 'dummy-ssh-keys',
          value: 'false',
        },
      ]
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test11Rule(data, Result.FAIL)
    })
  })

  describe('GCP PCI 1.2 Ensure that instances are not configured to use the default service account', () => {
    const gettest12RuleFixture = (
      metadataItems: MetadataItem[]
    ): CIS1xQueryResponse => {
      return {
        querygcpVmInstance: [
          {
            id: cuid(),
            name: 'dummy-project-name',
            project: [],
            labels: [],
            serviceAccounts: [],
            metadata: {
              items: metadataItems,
            },
          },
        ],
      }
    }

    const test12Rule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_12 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ¨block-project-ssh-keys¨ is set to false', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: 'false',
        },
      ]
      const data: CIS1xQueryResponse = gettest12RuleFixture(metadataItems)
      await test12Rule(data, Result.PASS)
    })

    test('No Security Issue when ¨serial-port-enable¨ is set to 0', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: '0',
        },
      ]
      const data: CIS1xQueryResponse = gettest12RuleFixture(metadataItems)
      await test12Rule(data, Result.PASS)
    })

    test('Security Security Issue when ¨serial-port-enable¨ is set to true', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: 'true',
        },
      ]
      const data: CIS1xQueryResponse = gettest12RuleFixture(metadataItems)
      await test12Rule(data, Result.FAIL)
    })

    test('Security Security Issue when ¨serial-port-enable¨ is set to 1', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: 'true',
        },
      ]
      const data: CIS1xQueryResponse = gettest12RuleFixture(metadataItems)
      await test12Rule(data, Result.FAIL)
    })

    test('Security Security Issue when ¨serial-port-enable¨ is set to 1', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: '1',
        },
      ]
      const data: CIS1xQueryResponse = gettest12RuleFixture(metadataItems)
      await test12Rule(data, Result.FAIL)
    })

    test('Security Security Issue when metadata is empty', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: '1',
        },
      ]
      const data: CIS1xQueryResponse = gettest12RuleFixture(metadataItems)
      await test12Rule(data, Result.FAIL)
    })

    test('Security Security Issue when metadata does NOT contain ¨serial-port-enable¨ key', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'dummy-key',
          value: 'false',
        },
      ]
      const data: CIS1xQueryResponse = gettest12RuleFixture(metadataItems)
      await test12Rule(data, Result.FAIL)
    })
  })
  
  describe('GCP PCI 1.3 Ensure that Cloud SQL database instances are not open to the world', () => {
    const getRule13Fixture = (): CIS1xQueryResponse => {
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

    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_13 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when authorizedNetworks is NOT set to '0.0.0.0/0'", async () => {
      const data: CIS1xQueryResponse = getRule13Fixture()
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when authorizedNetworks is empty', async () => {
      const data: CIS1xQueryResponse = getRule13Fixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      sqlInstance.settings = {
        ipConfiguration: {
          authorizedNetworks: [],
        },
        databaseFlags: [],
      }
      await testRule(data, Result.PASS)
    })

    test("Security Issue when authorizedNetworks is set to '0.0.0.0/0'", async () => {
      const data: CIS1xQueryResponse = getRule13Fixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      sqlInstance.settings = {
        ipConfiguration: {
          authorizedNetworks: [{ value: '0.0.0.0/0' }],
        },
        databaseFlags: [],
      }
      await testRule(data, Result.FAIL)
    })
  })

})
