import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_NIST_800_53_11 from '../rules/gcp-nist-800-53-rev4-1.1'
import Gcp_NIST_800_53_12 from '../rules/gcp-nist-800-53-rev4-1.2'
import Gcp_NIST_800_53_13 from '../rules/gcp-nist-800-53-rev4-1.3'
import Gcp_NIST_800_53_14 from '../rules/gcp-nist-800-53-rev4-1.4'
import Gcp_NIST_800_53_15 from '../rules/gcp-nist-800-53-rev4-1.5'
import Gcp_NIST_800_53_16 from '../rules/gcp-nist-800-53-rev4-1.6'
import Gcp_NIST_800_53_17 from '../rules/gcp-nist-800-53-rev4-1.7'

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

export interface ComputeProject {
  commonInstanceMetadata: Metadata
}

export interface QuerygcpProject {
  id: string
  computeProject?: ComputeProject[]
  vmInstances?: QuerygcpVmInstance[]
}

export interface QuerygcpSqlInstance {
  id?: string
  name: string
  settings: Settings
  ipAddresses?: IpAddress[]
}

export interface NIST1xQueryResponse {
  querygcpVmInstance?: QuerygcpVmInstance[]
  querygcpProject?: QuerygcpProject[]
  querygcpSqlInstance?: QuerygcpSqlInstance[]
}

describe('GCP NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'NIST'} )
  })

  describe('GCP NIST 1.1 Compute instances should not use the default service account', () => {
    const getTest41RuleFixture = (
      name: string,
      projects: Project[],
      labels: Label[],
      serviceAccounts: ServiceAccount[]
    ): NIST1xQueryResponse => {
      return {
        querygcpVmInstance: [
          {
            id: cuid(),
            name,
            project: projects,
            labels,
            serviceAccounts,
          },
        ],
      }
    }

    const test41Rule = async (
      data: NIST1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_11 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when the vm name starts with "gke-", it has a "goog-gke-node" label and the service account is the default compute service account', async () => {
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
      const data: NIST1xQueryResponse = getTest41RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test41Rule(data, Result.PASS)
    })

    test('No Security Issue when the vm name starts with "gke-", it does NOT have a "goog-gke-node" label but the service account is NOT the default compute service account', async () => {
      const name = 'gke-test'
      const projects: Project[] = [{ id: 'projects/dummy-id' }]
      const labels: Label[] = []
      const serviceAccounts: ServiceAccount[] = [
        {
          email: 'dummy-compute@test.com',
        },
      ]
      const data: NIST1xQueryResponse = getTest41RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test41Rule(data, Result.PASS)
    })

    test('No Security Issue when the vm name does NOT start with "gke-", it has a "goog-gke-node" label but the service account is NOT the default compute service account', async () => {
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
      const data: NIST1xQueryResponse = getTest41RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test41Rule(data, Result.PASS)
    })

    test('No Security Issue when the vm name does NOT start with "gke-", it does NOT have a "goog-gke-node" label but the service account is NOT the default compute service account', async () => {
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
      const data: NIST1xQueryResponse = getTest41RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test41Rule(data, Result.PASS)
    })

    test('Security Issue when the vm name does NOT start with "gke-", it does NOT have a "goog-gke-node" label and the service account is the default compute service account', async () => {
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
      const data: NIST1xQueryResponse = getTest41RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test41Rule(data, Result.FAIL)
    })

    test('Security Issue when the vm name does start with "gke-", it does NOT have a "goog-gke-node" label and the service account is the default compute service account', async () => {
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
      const data: NIST1xQueryResponse = getTest41RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test41Rule(data, Result.FAIL)
    })

    test('Security Issue when the vm name does start with "gke-", it does NOT have any label and the service account is the default compute service account', async () => {
      const name = 'gke-test'
      const labels: Label[] = []
      const projectId = 123456789
      const projects: Project[] = [{ id: `projects/${projectId}` }]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: `${projectId}-compute@developer.gserviceaccount.com`,
        },
      ]
      const data: NIST1xQueryResponse = getTest41RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test41Rule(data, Result.FAIL)
    })

    test('Security Issue when the vm name does NOT start with "gke-", it does have a "goog-gke-node" label and the service account is the default compute service account', async () => {
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
      const data: NIST1xQueryResponse = getTest41RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test41Rule(data, Result.FAIL)
    })
  })

  describe('GCP NIST 1.2 Compute instances should not use the default service account with full access to all Cloud APIs', () => {
    const getTest42RuleFixture = (
      name: string,
      projects: Project[],
      labels: Label[],
      serviceAccounts: ServiceAccount[]
    ): NIST1xQueryResponse => {
      return {
        querygcpVmInstance: [
          {
            id: cuid(),
            name,
            project: projects,
            labels,
            serviceAccounts,
          },
        ],
      }
    }

    const test42Rule = async (
      data: NIST1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_12 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test(`No Security Issue when the vm name starts with "gke-",
    it has a "goog-gke-node" label
    and the service account is the default compute service account
    but it does NOT have the "cloud-platform" scope`, async () => {
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
          scopes: ['https://www.googleapis.com/auth/cloud-platform'],
        },
      ]
      const data: NIST1xQueryResponse = getTest42RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test42Rule(data, Result.PASS)
    })

    test(`No Security Issue when the vm name starts with "gke-",
    it does NOT have a "goog-gke-node" label,
    the service account is NOT the default compute service account,
    and it has the "cloud-platform" scope`, async () => {
      const name = 'gke-test'
      const projects: Project[] = [{ id: 'projects/dummy-id' }]
      const labels: Label[] = []
      const serviceAccounts: ServiceAccount[] = [
        {
          email: 'dummy-compute@test.com',
          scopes: [],
        },
      ]
      const data: NIST1xQueryResponse = getTest42RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test42Rule(data, Result.PASS)
    })

    test('No Security Issue when the vm name does NOT start with "gke-", it has a "goog-gke-node" label but the service account is NOT the default compute service account', async () => {
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
          scopes: ['https://www.googleapis.com/auth/cloud-platform'],
        },
      ]
      const data: NIST1xQueryResponse = getTest42RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test42Rule(data, Result.PASS)
    })

    test(`No Security Issue when the vm name does NOT start with "gke-",
    it does NOT have a "goog-gke-node" label,
    the service account is NOT the default compute service account
    and it has the "cloud-platform" scope`, async () => {
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
          scopes: ['https://www.googleapis.com/auth/cloud-platform'],
        },
      ]
      const data: NIST1xQueryResponse = getTest42RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test42Rule(data, Result.PASS)
    })

    test(`Security Issue when the vm name does NOT start with "gke-",
     it does NOT have a "goog-gke-node" label,
     the service account is the default compute service account,
     and it has the "cloud-platform" scope`, async () => {
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
          scopes: ['https://www.googleapis.com/auth/cloud-platform'],
        },
      ]
      const data: NIST1xQueryResponse = getTest42RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test42Rule(data, Result.FAIL)
    })

    test(`Security Issue when the vm name does start with "gke-",
    it does NOT have a "goog-gke-node" label,
    the service account is the default compute service account,
    and it has the "cloud-platform" scope`, async () => {
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
          scopes: ['https://www.googleapis.com/auth/cloud-platform'],
        },
      ]
      const data: NIST1xQueryResponse = getTest42RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test42Rule(data, Result.FAIL)
    })

    test(`Security Issue when the vm name does start with "gke-",
    it does NOT have any label,
    the service account is the default compute service account,
    and it has the "cloud-platform" scope`, async () => {
      const name = 'gke-test'
      const labels: Label[] = []
      const projectId = 123456789
      const projects: Project[] = [{ id: `projects/${projectId}` }]
      const serviceAccounts: ServiceAccount[] = [
        {
          email: `${projectId}-compute@developer.gserviceaccount.com`,
          scopes: ['https://www.googleapis.com/auth/cloud-platform'],
        },
      ]
      const data: NIST1xQueryResponse = getTest42RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test42Rule(data, Result.FAIL)
    })

    test(`Security Issue when the vm name does NOT start with "gke-",
    it does have a "goog-gke-node" label
    the service account is the default compute service account
    and it has the "cloud-platform" scope`, async () => {
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
          scopes: ['https://www.googleapis.com/auth/cloud-platform'],
        },
      ]
      const data: NIST1xQueryResponse = getTest42RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test42Rule(data, Result.FAIL)
    })
  })

  describe('GCP NIST 1.3 Compute instance "block-project-ssh-keys should be enabled', () => {
    const getTest43RuleFixture = (
      name: string,
      projects: Project[],
      labels: Label[],
      serviceAccounts: ServiceAccount[],
      metadataItems: MetadataItem[]
    ): NIST1xQueryResponse => {
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

    const test43Rule = async (
      data: NIST1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_13 as Rule,
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.PASS)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.PASS)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.PASS)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.PASS)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.PASS)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.FAIL)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.FAIL)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.FAIL)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.FAIL)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.FAIL)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.FAIL)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.FAIL)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.FAIL)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.FAIL)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.FAIL)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.FAIL)
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
      const data: NIST1xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.FAIL)
    })
  })

  describe('GCP NIST 1.4 Compute instances should not have public IP addresses', () => {
    const test49Rule = async (
      instanceName: string,
      natIP: string | null,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: NIST1xQueryResponse = {
        querygcpVmInstance: [
          {
            id: cuid(),
            name: instanceName,
            networkInterfaces: [
              {
                accessConfigs: [
                  {
                    natIP,
                  },
                ],
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_14 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with an instance cretaed by GKE with natIP', async () => {
      await test49Rule('gke-instance-1', '34.69.30.133', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with an instance cretaed by GKE without natIp', async () => {
      await test49Rule('gke-instance-1', '34.69.30.133', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random instance without natIP', async () => {
      await test49Rule('instance-1', null, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a random instance with natIP', async () => {
      await test49Rule('instance-1', '34.69.30.133', Result.FAIL)
    })
  })

  describe('GCP NIST 1.5 Compute instances "Enable connecting to serial ports" should not be enabled', () => {
    const getTest45RuleFixture = (
      metadataItems: MetadataItem[]
    ): NIST1xQueryResponse => {
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

    const test45Rule = async (
      data: NIST1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_15 as Rule,
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
      const data: NIST1xQueryResponse = getTest45RuleFixture(metadataItems)
      await test45Rule(data, Result.PASS)
    })

    test('No Security Issue when ¨serial-port-enable¨ is set to 0', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: '0',
        },
      ]
      const data: NIST1xQueryResponse = getTest45RuleFixture(metadataItems)
      await test45Rule(data, Result.PASS)
    })

    test('Security Security Issue when ¨serial-port-enable¨ is set to true', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: 'true',
        },
      ]
      const data: NIST1xQueryResponse = getTest45RuleFixture(metadataItems)
      await test45Rule(data, Result.FAIL)
    })

    test('Security Security Issue when ¨serial-port-enable¨ is set to 1', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: 'true',
        },
      ]
      const data: NIST1xQueryResponse = getTest45RuleFixture(metadataItems)
      await test45Rule(data, Result.FAIL)
    })

    test('Security Security Issue when ¨serial-port-enable¨ is set to 1', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: '1',
        },
      ]
      const data: NIST1xQueryResponse = getTest45RuleFixture(metadataItems)
      await test45Rule(data, Result.FAIL)
    })

    test('Security Security Issue when metadata is empty', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: '1',
        },
      ]
      const data: NIST1xQueryResponse = getTest45RuleFixture(metadataItems)
      await test45Rule(data, Result.FAIL)
    })

    test('Security Security Issue when metadata does NOT contain ¨serial-port-enable¨ key', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'dummy-key',
          value: 'false',
        },
      ]
      const data: NIST1xQueryResponse = getTest45RuleFixture(metadataItems)
      await test45Rule(data, Result.FAIL)
    })
  })

  describe('GCP NIST 1.6 SQL database instances should not permit access from 0.0.0.0/0', () => {
    const getRuleFixture = (): NIST1xQueryResponse => {
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
      data: NIST1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_16 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when authorizedNetworks is NOT set to '0.0.0.0/0'", async () => {
      const data: NIST1xQueryResponse = getRuleFixture()
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when authorizedNetworks is empty', async () => {
      const data: NIST1xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as QuerygcpSqlInstance
      sqlInstance.settings = {
        ipConfiguration: {
          authorizedNetworks: [],
        },
        databaseFlags: [],
      }
      await testRule(data, Result.PASS)
    })

    test("Security Issue when authorizedNetworks is set to '0.0.0.0/0'", async () => {
      const data: NIST1xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as QuerygcpSqlInstance
      sqlInstance.settings = {
        ipConfiguration: {
          authorizedNetworks: [{ value: '0.0.0.0/0' }],
        },
        databaseFlags: [],
      }
      await testRule(data, Result.FAIL)
    })
  })

  describe('GCP NIST 1.7 SQL database instances should not have public IPs', () => {
    const getRuleFixture = (): NIST1xQueryResponse => {
      return {
        querygcpSqlInstance: [
          {
            id: cuid(),
            name: 'test-sql-instance',
            ipAddresses: [
              {
                type: 'PRIVATE',
              },
            ],
            settings: {
              databaseFlags: [],
            },
          },
        ],
      }
    }

    const testRule = async (
      data: NIST1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_17 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ipAddresses are PRIVATE', async () => {
      const data: NIST1xQueryResponse = getRuleFixture()
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when ipAddresses are empty', async () => {
      const data: NIST1xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as QuerygcpSqlInstance
      sqlInstance.ipAddresses = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when ipAddresses are PUBLIC', async () => {
      const data: NIST1xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as QuerygcpSqlInstance
      sqlInstance.ipAddresses = [
        {
          type: 'PUBLIC',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when ipAddresses are PRIVATE and PUBLIC', async () => {
      const data: NIST1xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as QuerygcpSqlInstance
      sqlInstance.ipAddresses = [
        {
          type: 'PRIVATE',
        },
        {
          type: 'PUBLIC',
        },
      ]
      await testRule(data, Result.FAIL)
    })
  })
})
