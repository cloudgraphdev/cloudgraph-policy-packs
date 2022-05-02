/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Gcp_CIS_120_41 from '../rules/gcp-cis-1.2.0-4.1'
import Gcp_CIS_120_42 from '../rules/gcp-cis-1.2.0-4.2'
import Gcp_CIS_120_43 from '../rules/gcp-cis-1.2.0-4.3'
import Gcp_CIS_120_44 from '../rules/gcp-cis-1.2.0-4.4'
import Gcp_CIS_120_45 from '../rules/gcp-cis-1.2.0-4.5'
import Gcp_CIS_120_46 from '../rules/gcp-cis-1.2.0-4.6'
import Gcp_CIS_120_47 from '../rules/gcp-cis-1.2.0-4.7'
import Gcp_CIS_120_48 from '../rules/gcp-cis-1.2.0-4.8'
import Gcp_CIS_120_49 from '../rules/gcp-cis-1.2.0-4.9'
import Gcp_CIS_120_411 from '../rules/gcp-cis-1.2.0-4.11'

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

export interface CIS4xQueryResponse {
  querygcpVmInstance?: QuerygcpVmInstance[]
  querygcpProject?: QuerygcpProject[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'CIS'} )
  })

  describe('GCP CIS 4.1 Ensure that instances are not configured to use the default service account', () => {
    const getTest41RuleFixture = (
      name: string,
      projects: Project[],
      labels: Label[],
      serviceAccounts: ServiceAccount[]
    ): CIS4xQueryResponse => {
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
      data: CIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_41 as Rule,
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
      const data: CIS4xQueryResponse = getTest41RuleFixture(
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
      const data: CIS4xQueryResponse = getTest41RuleFixture(
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
      const data: CIS4xQueryResponse = getTest41RuleFixture(
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
      const data: CIS4xQueryResponse = getTest41RuleFixture(
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
      const data: CIS4xQueryResponse = getTest41RuleFixture(
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
      const data: CIS4xQueryResponse = getTest41RuleFixture(
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
      const data: CIS4xQueryResponse = getTest41RuleFixture(
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
      const data: CIS4xQueryResponse = getTest41RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test41Rule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 4.2 Ensure that instances are not configured to use the default service account with full access to all Cloud APIs', () => {
    const getTest42RuleFixture = (
      name: string,
      projects: Project[],
      labels: Label[],
      serviceAccounts: ServiceAccount[]
    ): CIS4xQueryResponse => {
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
      data: CIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_42 as Rule,
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
      const data: CIS4xQueryResponse = getTest42RuleFixture(
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
      const data: CIS4xQueryResponse = getTest42RuleFixture(
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
      const data: CIS4xQueryResponse = getTest42RuleFixture(
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
      const data: CIS4xQueryResponse = getTest42RuleFixture(
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
      const data: CIS4xQueryResponse = getTest42RuleFixture(
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
      const data: CIS4xQueryResponse = getTest42RuleFixture(
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
      const data: CIS4xQueryResponse = getTest42RuleFixture(
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
      const data: CIS4xQueryResponse = getTest42RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test42Rule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 4.3 Ensure "Block Project-wide SSH keys" is enabled for VM instances', () => {
    const getTest43RuleFixture = (
      name: string,
      projects: Project[],
      labels: Label[],
      serviceAccounts: ServiceAccount[],
      metadataItems: MetadataItem[]
    ): CIS4xQueryResponse => {
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
      data: CIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_43 as Rule,
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
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
      const data: CIS4xQueryResponse = getTest43RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await test43Rule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 4.4 Ensure oslogin is enabled for a Project', () => {
    const getTest44RuleFixture = (): CIS4xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            computeProject: [
              {
                commonInstanceMetadata: {
                  items: [
                    {
                      key: 'enable-oslogin',
                      value: 'true',
                    },
                  ],
                },
              },
            ],
            vmInstances: [
              {
                id: cuid(),
                metadata: {
                  items: [
                    {
                      key: 'created-by',
                      value: 'dummy',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const test44Rule = async (
      data: CIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_44 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when the oslogin is enabled for a Project and is not overriden by VM metadata', async () => {
      const data: CIS4xQueryResponse = getTest44RuleFixture()
      await test44Rule(data, Result.PASS)
    })

    test('No Security Issue when the oslogin is enabled for a Project and empty VM metadata items', async () => {
      const data: CIS4xQueryResponse = getTest44RuleFixture()
      const projects = data.querygcpProject as QuerygcpProject[]
      const project = projects[0] as QuerygcpProject
      project.vmInstances = [
        {
          id: cuid(),
          metadata: {
            items: [],
          },
        },
      ]
      await test44Rule(data, Result.PASS)
    })

    test('No Security Issue when the oslogin is enabled for a Project and no VMs', async () => {
      const data: CIS4xQueryResponse = getTest44RuleFixture()
      const projects = data.querygcpProject as QuerygcpProject[]
      const project = projects[0] as QuerygcpProject
      project.vmInstances = []
      await test44Rule(data, Result.PASS)
    })

    test('Security Issue when the oslogin is NOT enabled for a Project and is not overriden by VM metadata', async () => {
      const data: CIS4xQueryResponse = {
        querygcpProject: [
          {
            id: cuid(),
            computeProject: [
              {
                commonInstanceMetadata: {
                  items: [
                    {
                      key: 'enable-oslogin',
                      value: 'false',
                    },
                  ],
                },
              },
            ],
            vmInstances: [],
          },
        ],
      }

      await test44Rule(data, Result.FAIL)
    })

    test('Security Issue when the oslogin is enabled for a Project BUT and is overriden by VM metadata', async () => {
      const data: CIS4xQueryResponse = {
        querygcpProject: [
          {
            id: cuid(),
            computeProject: [
              {
                commonInstanceMetadata: {
                  items: [
                    {
                      key: 'enable-oslogin',
                      value: 'true',
                    },
                  ],
                },
              },
            ],
            vmInstances: [
              {
                id: cuid(),
                metadata: {
                  items: [
                    {
                      key: 'enable-oslogin',
                      value: 'false',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }

      await test44Rule(data, Result.FAIL)
    })

    test('Security Issue when the oslogin is enabled for a Project BUT and is overriden by VM metadata (and key is duplicated)', async () => {
      const data: CIS4xQueryResponse = {
        querygcpProject: [
          {
            id: cuid(),
            computeProject: [
              {
                commonInstanceMetadata: {
                  items: [
                    {
                      key: 'enable-oslogin',
                      value: 'true',
                    },
                  ],
                },
              },
            ],
            vmInstances: [
              {
                id: cuid(),
                metadata: {
                  items: [
                    {
                      key: 'enable-oslogin',
                      value: 'true',
                    },
                    {
                      key: 'enable-oslogin',
                      value: 'false',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }

      await test44Rule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 4.5 Ensure that instances are not configured to use the default service account', () => {
    const getTest45RuleFixture = (
      metadataItems: MetadataItem[]
    ): CIS4xQueryResponse => {
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
      data: CIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_45 as Rule,
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
      const data: CIS4xQueryResponse = getTest45RuleFixture(metadataItems)
      await test45Rule(data, Result.PASS)
    })

    test('No Security Issue when ¨serial-port-enable¨ is set to 0', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: '0',
        },
      ]
      const data: CIS4xQueryResponse = getTest45RuleFixture(metadataItems)
      await test45Rule(data, Result.PASS)
    })

    test('Security Security Issue when ¨serial-port-enable¨ is set to true', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: 'true',
        },
      ]
      const data: CIS4xQueryResponse = getTest45RuleFixture(metadataItems)
      await test45Rule(data, Result.FAIL)
    })

    test('Security Security Issue when ¨serial-port-enable¨ is set to 1', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: 'true',
        },
      ]
      const data: CIS4xQueryResponse = getTest45RuleFixture(metadataItems)
      await test45Rule(data, Result.FAIL)
    })

    test('Security Security Issue when ¨serial-port-enable¨ is set to 1', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: '1',
        },
      ]
      const data: CIS4xQueryResponse = getTest45RuleFixture(metadataItems)
      await test45Rule(data, Result.FAIL)
    })

    test('Security Security Issue when metadata is empty', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: '1',
        },
      ]
      const data: CIS4xQueryResponse = getTest45RuleFixture(metadataItems)
      await test45Rule(data, Result.FAIL)
    })

    test('Security Security Issue when metadata does NOT contain ¨serial-port-enable¨ key', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'dummy-key',
          value: 'false',
        },
      ]
      const data: CIS4xQueryResponse = getTest45RuleFixture(metadataItems)
      await test45Rule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 4.6 Ensure that IP forwarding is not enabled on Instances', () => {
    const getTest46RuleFixture = (
      canIpForward: boolean
    ): CIS4xQueryResponse => {
      return {
        querygcpVmInstance: [
          {
            id: cuid(),
            name: 'dummy-project-name',
            canIpForward,
            project: [],
            labels: [],
          },
        ],
      }
    }

    const test46Rule = async (
      data: CIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_46 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when canIpForward is false', async () => {
      const data: CIS4xQueryResponse = getTest46RuleFixture(false)
      await test46Rule(data, Result.PASS)
    })

    test('Security Issue when canIpForward is true', async () => {
      const data: CIS4xQueryResponse = getTest46RuleFixture(true)
      await test46Rule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 4.7 Ensure VM disks for critical VMs are encrypted with Customer-Supplied Encryption Keys (CSEK)', () => {
    const getTest47RuleFixture = (disk: Disk): CIS4xQueryResponse => {
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

    const test47Rule = async (
      data: CIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_47 as Rule,
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

      const data: CIS4xQueryResponse = getTest47RuleFixture(disk)
      await test47Rule(data, Result.PASS)
    })

    test('Security Issue when disk diskEncryptionKey is null', async () => {
      const disk: Disk = {
        diskEncryptionKey: null,
      }

      const data: CIS4xQueryResponse = getTest47RuleFixture(disk)
      await test47Rule(data, Result.FAIL)
    })

    test('Security Issue when disk diskEncryptionKey sha256 is null', async () => {
      const disk: Disk = {
        diskEncryptionKey: {
          sha256: null,
        },
      }

      const data: CIS4xQueryResponse = getTest47RuleFixture(disk)
      await test47Rule(data, Result.FAIL)
    })

    test('Security Issue when disk diskEncryptionKey sha256 is empty', async () => {
      const disk: Disk = {
        diskEncryptionKey: {
          sha256: '',
        },
      }

      const data: CIS4xQueryResponse = getTest47RuleFixture(disk)
      await test47Rule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 4.8 Ensure Compute instances are launched with Shielded VM enabled', () => {
    const test48Rule = async (
      enableIntegrityMonitoring: boolean,
      enableVtpm: boolean,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS4xQueryResponse = {
        querygcpVmInstance: [
          {
            id: cuid(),
            shieldedInstanceConfig: {
              enableIntegrityMonitoring,
              enableVtpm,
            },
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_48 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a shieldedInstanceConfig with enableIntegrityMonitoring and enableVtpm enabled', async () => {
      await test48Rule(true, true, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a shieldedInstanceConfig with enableIntegrityMonitoring and enableVtpm disabled', async () => {
      await test48Rule(false, false, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with a shieldedInstanceConfig with enableIntegrityMonitoring enabled and enableVtpm disabled', async () => {
      await test48Rule(true, false, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with a shieldedInstanceConfig with enableIntegrityMonitoring disabled and enableVtpm enabled', async () => {
      await test48Rule(false, true, Result.FAIL)
    })
  })

  describe('GCP CIS 4.9 Ensure that Compute instances do not have public IP addresses', () => {
    const test49Rule = async (
      instanceName: string,
      natIP: string | null,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS4xQueryResponse = {
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
        Gcp_CIS_120_49 as Rule,
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

  describe('GCP CIS 4.11 Ensure Compute instances are launched with Shielded VM enabled', () => {
    const test411Rule = async (
      enableConfidentialCompute: boolean,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS4xQueryResponse = {
        querygcpVmInstance: [
          {
            id: cuid(),
            confidentialInstanceConfig: {
              enableConfidentialCompute,
            },
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_411 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a confidentialInstanceConfig with enableConfidentialCompute enabled', async () => {
      await test411Rule(true, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a confidentialInstanceConfig with enableConfidentialCompute disabled', async () => {
      await test411Rule(false, Result.FAIL)
    })
  })
})
