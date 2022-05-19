import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_PCI_DSS_321_21 from '../rules/pci-dss-3.2.1-2.1'
import Gcp_PCI_DSS_321_22 from '../rules/pci-dss-3.2.1-2.2'

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

export interface CIS2xQueryResponse {
  querygcpVmInstance?: QuerygcpVmInstance[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'PCI'} )
  })

  describe('GCP PCI 2.1 Ensure that instances are not configured to use the default service account', () => {
    const getTest21RuleFixture = (
      name: string,
      projects: Project[],
      labels: Label[],
      serviceAccounts: ServiceAccount[]
    ): CIS2xQueryResponse => {
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

    const test21Rule = async (
      data: CIS2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_21 as Rule,
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
      const data: CIS2xQueryResponse = getTest21RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test21Rule(data, Result.PASS)
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
      const data: CIS2xQueryResponse = getTest21RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test21Rule(data, Result.PASS)
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
      const data: CIS2xQueryResponse = getTest21RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test21Rule(data, Result.PASS)
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
      const data: CIS2xQueryResponse = getTest21RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test21Rule(data, Result.PASS)
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
      const data: CIS2xQueryResponse = getTest21RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test21Rule(data, Result.FAIL)
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
      const data: CIS2xQueryResponse = getTest21RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test21Rule(data, Result.FAIL)
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
      const data: CIS2xQueryResponse = getTest21RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test21Rule(data, Result.FAIL)
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
      const data: CIS2xQueryResponse = getTest21RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test21Rule(data, Result.FAIL)
    })
  })

  describe('GCP PCI 2.2 Ensure that instances are not configured to use the default service account with full access to all Cloud APIs', () => {
    const getTest22RuleFixture = (
      name: string,
      projects: Project[],
      labels: Label[],
      serviceAccounts: ServiceAccount[]
    ): CIS2xQueryResponse => {
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

    const test22Rule = async (
      data: CIS2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_22 as Rule,
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
      const data: CIS2xQueryResponse = getTest22RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test22Rule(data, Result.PASS)
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
      const data: CIS2xQueryResponse = getTest22RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test22Rule(data, Result.PASS)
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
      const data: CIS2xQueryResponse = getTest22RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test22Rule(data, Result.PASS)
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
      const data: CIS2xQueryResponse = getTest22RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test22Rule(data, Result.PASS)
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
      const data: CIS2xQueryResponse = getTest22RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test22Rule(data, Result.FAIL)
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
      const data: CIS2xQueryResponse = getTest22RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test22Rule(data, Result.FAIL)
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
      const data: CIS2xQueryResponse = getTest22RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test22Rule(data, Result.FAIL)
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
      const data: CIS2xQueryResponse = getTest22RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await test22Rule(data, Result.FAIL)
    })
  })

})
