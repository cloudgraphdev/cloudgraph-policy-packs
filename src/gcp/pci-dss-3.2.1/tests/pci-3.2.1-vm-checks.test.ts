import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_PCI_DSS_321_VM_1 from '../rules/pci-dss-3.2.1-vm-check-1'
import Gcp_PCI_DSS_321_VM_2 from '../rules/pci-dss-3.2.1-vm-check-2'
import Gcp_PCI_DSS_321_VM_3 from '../rules/pci-dss-3.2.1-vm-check-3'
import Gcp_PCI_DSS_321_VM_4 from '../rules/pci-dss-3.2.1-vm-check-4'

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

export interface CISVMQueryResponse {
  querygcpVmInstance?: QuerygcpVmInstance[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'PCI'} )
  })

  describe('VM Check 1: Ensure "Block Project-wide SSH keys" is enabled for VM instances', () => {
    const getTestVM1RuleFixture = (
      name: string,
      projects: Project[],
      labels: Label[],
      serviceAccounts: ServiceAccount[],
      metadataItems: MetadataItem[]
    ): CISVMQueryResponse => {
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

    const testVM1Rule = async (
      data: CISVMQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_VM_1 as Rule,
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.PASS)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.PASS)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.PASS)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.PASS)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.PASS)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM1RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts,
        metadataItems
      )
      await testVM1Rule(data, Result.FAIL)
    })
  })

  describe('VM Check 2: Ensure that instances are not configured to use the default service account', () => {
    const gettestVM2RuleFixture = (
      metadataItems: MetadataItem[]
    ): CISVMQueryResponse => {
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

    const testVM2Rule = async (
      data: CISVMQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_VM_2 as Rule,
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
      const data: CISVMQueryResponse = gettestVM2RuleFixture(metadataItems)
      await testVM2Rule(data, Result.PASS)
    })

    test('No Security Issue when ¨serial-port-enable¨ is set to 0', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: '0',
        },
      ]
      const data: CISVMQueryResponse = gettestVM2RuleFixture(metadataItems)
      await testVM2Rule(data, Result.PASS)
    })

    test('Security Security Issue when ¨serial-port-enable¨ is set to true', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: 'true',
        },
      ]
      const data: CISVMQueryResponse = gettestVM2RuleFixture(metadataItems)
      await testVM2Rule(data, Result.FAIL)
    })

    test('Security Security Issue when ¨serial-port-enable¨ is set to 1', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: 'true',
        },
      ]
      const data: CISVMQueryResponse = gettestVM2RuleFixture(metadataItems)
      await testVM2Rule(data, Result.FAIL)
    })

    test('Security Security Issue when ¨serial-port-enable¨ is set to 1', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: '1',
        },
      ]
      const data: CISVMQueryResponse = gettestVM2RuleFixture(metadataItems)
      await testVM2Rule(data, Result.FAIL)
    })

    test('Security Security Issue when metadata is empty', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'serial-port-enable',
          value: '1',
        },
      ]
      const data: CISVMQueryResponse = gettestVM2RuleFixture(metadataItems)
      await testVM2Rule(data, Result.FAIL)
    })

    test('Security Security Issue when metadata does NOT contain ¨serial-port-enable¨ key', async () => {
      const metadataItems: MetadataItem[] = [
        {
          key: 'dummy-key',
          value: 'false',
        },
      ]
      const data: CISVMQueryResponse = gettestVM2RuleFixture(metadataItems)
      await testVM2Rule(data, Result.FAIL)
    })
  })
  
  describe('VM Check 3: Ensure that instances are not configured to use the default service account', () => {
    const getTestVM3RuleFixture = (
      name: string,
      projects: Project[],
      labels: Label[],
      serviceAccounts: ServiceAccount[]
    ): CISVMQueryResponse => {
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

    const testVM3Rule = async (
      data: CISVMQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_VM_3 as Rule,
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
      const data: CISVMQueryResponse = getTestVM3RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM3Rule(data, Result.PASS)
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
      const data: CISVMQueryResponse = getTestVM3RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM3Rule(data, Result.PASS)
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
      const data: CISVMQueryResponse = getTestVM3RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM3Rule(data, Result.PASS)
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
      const data: CISVMQueryResponse = getTestVM3RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM3Rule(data, Result.PASS)
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
      const data: CISVMQueryResponse = getTestVM3RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM3Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM3RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM3Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM3RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM3Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM3RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM3Rule(data, Result.FAIL)
    })
  })

  describe('VM Check 4: Ensure that instances are not configured to use the default service account with full access to all Cloud APIs', () => {
    const getTestVM4RuleFixture = (
      name: string,
      projects: Project[],
      labels: Label[],
      serviceAccounts: ServiceAccount[]
    ): CISVMQueryResponse => {
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

    const testVM4Rule = async (
      data: CISVMQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_VM_4 as Rule,
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
      const data: CISVMQueryResponse = getTestVM4RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM4Rule(data, Result.PASS)
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
      const data: CISVMQueryResponse = getTestVM4RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM4Rule(data, Result.PASS)
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
      const data: CISVMQueryResponse = getTestVM4RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM4Rule(data, Result.PASS)
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
      const data: CISVMQueryResponse = getTestVM4RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM4Rule(data, Result.PASS)
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
      const data: CISVMQueryResponse = getTestVM4RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM4Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM4RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM4Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM4RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM4Rule(data, Result.FAIL)
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
      const data: CISVMQueryResponse = getTestVM4RuleFixture(
        name,
        projects,
        labels,
        serviceAccounts
      )
      await testVM4Rule(data, Result.FAIL)
    })
  })

})
