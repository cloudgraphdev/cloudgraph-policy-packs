import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_PCI_DSS_321_Monitoring_1 from '../rules/pci-dss-3.2.1-monitoring-check-1'
import Gcp_PCI_DSS_321_Monitoring_2 from '../rules/pci-dss-3.2.1-monitoring-check-2'
import Gcp_PCI_DSS_321_Monitoring_3 from '../rules/pci-dss-3.2.1-monitoring-check-3'
import Gcp_PCI_DSS_321_Monitoring_4 from '../rules/pci-dss-3.2.1-monitoring-check-4'
import Gcp_PCI_DSS_321_Monitoring_5 from '../rules/pci-dss-3.2.1-monitoring-check-5'
import Gcp_PCI_DSS_321_Monitoring_6 from '../rules/pci-dss-3.2.1-monitoring-check-6'
import Gcp_PCI_DSS_321_Monitoring_7 from '../rules/pci-dss-3.2.1-monitoring-check-7'
import Gcp_PCI_DSS_321_Monitoring_8 from '../rules/pci-dss-3.2.1-monitoring-check-8'

const Gcp_PCI_DSS_321_Monitoring_1_Filter =
  'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*'
const Gcp_PCI_DSS_321_Monitoring_2_Filter =
  'resource.type="iam_role" AND protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole"'
const Gcp_PCI_DSS_321_Monitoring_3_Filter =
  'resource.type=gce_network AND protoPayload.methodName="beta.compute.networks.insert" OR protoPayload.methodName="beta.compute.networks.patch" OR protoPayload.methodName="v1.compute.networks.delete" OR protoPayload.methodName="v1.compute.networks.removePeering" OR protoPayload.methodName="v1.compute.networks.addPeering"'
const Gcp_PCI_DSS_321_Monitoring_4_Filter =
  'resource.type="gce_firewall_rule" AND protoPayload.methodName="v1.compute.firewalls.patch" OR protoPayload.methodName="v1.compute.firewalls.insert"'
const Gcp_PCI_DSS_321_Monitoring_5_Filter =
  'resource.type="gce_route" AND protoPayload.methodName="beta.compute.routes.patch" OR protoPayload.methodName="beta.compute.routes.insert"'
const Gcp_PCI_DSS_321_Monitoring_6_Filter =
  '( protoPayload.serviceName="cloudresourcemanager.googleapis.com" ) AND ( ProjectOwnership OR projectOwnerInvitee ) OR ( protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner" ) OR ( protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner" )'
const Gcp_PCI_DSS_321_Monitoring_7_Filter =
  'protoPayload.methodName="cloudsql.instances.update"'
const Gcp_PCI_DSS_321_Monitoring_8_Filter =
  'resource.type=gcs_bucket AND protoPayload.methodName="storage.setIamPermissions"'


export interface MetricDescriptor {
  type: string
}

export interface LogMetric {
  filter: string
  name?: string
  metricDescriptor?: MetricDescriptor
}

export interface Project {
  logMetrics?: LogMetric[]
}

export interface Enabled {
  value: boolean
}

export interface QuerygcpAlertPolicy {
  id: string
  enabled?: Enabled
  project?: Project[]
}

export interface DnsPolicy {
  enableLogging: boolean
}

export interface QuerygcpNetwork {
  id: string
  dnsPolicies?: DnsPolicy[]
}

export interface LogBucket {
  name: string
  retentionDays: number
  locked: boolean
}

export interface LogSink {
  filter?: string
  destination?: string
}

export interface QuerygcpProject {
  id: string
  logSinks: LogSink[]
  logBuckets?: LogBucket[]
}

export interface AuditLogConfig {
  logType: string
  exemptedMembers: string[]
}

export interface AuditConfig {
  auditLogConfigs: AuditLogConfig[]
  service: string
  exemptedMembers: string[]
}

export interface QuerygcpIamPolicy {
  id: string
  auditConfigs: AuditConfig[]
}

export interface PCIQueryResponse {
  querygcpAlertPolicy?: QuerygcpAlertPolicy[]
  querygcpNetwork?: QuerygcpNetwork[]
  querygcpProject?: QuerygcpProject[]
  querygcpIamPolicy?: QuerygcpIamPolicy[]
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'PCI'} )
  })

  describe('Monitoring check 1: Logging metric filter and alert for audit configuration changes should be configured', () => {
    const testRule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: PCIQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetrics: [
                  {
                    filter: 'dummy test filter',
                    name: 'dummy test name',
                    metricDescriptor: {
                      type: 'logging.googleapis.com/user/dummy-test-name',
                    },
                  },
                  {
                    filter,
                    name: metricName,
                    metricDescriptor: {
                      type: `logging.googleapis.com/user/${metricType}`,
                    },
                  },
                ],
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_Monitoring_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_1_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await testRule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await testRule(
        false,
        Gcp_PCI_DSS_321_Monitoring_1_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_1_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('Monitoring check 2: Logging metric filter and alert for Custom Role changes should be configured', () => {
    const testRule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: PCIQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetrics: [
                  {
                    filter: 'dummy test filter',
                    name: 'dummy test name',
                    metricDescriptor: {
                      type: 'logging.googleapis.com/user/dummy-test-name',
                    },
                  },
                  {
                    filter,
                    name: metricName,
                    metricDescriptor: {
                      type: `logging.googleapis.com/user/${metricType}`,
                    },
                  },
                ],
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_Monitoring_2 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_2_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await testRule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await testRule(
        false,
        Gcp_PCI_DSS_321_Monitoring_2_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_2_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('Monitoring check 3: Logging metric filter and alert for network changes should be configured', () => {
    const testRule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: PCIQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetrics: [
                  {
                    filter: 'dummy test filter',
                    name: 'dummy test name',
                    metricDescriptor: {
                      type: 'logging.googleapis.com/user/dummy-test-name',
                    },
                  },
                  {
                    filter,
                    name: metricName,
                    metricDescriptor: {
                      type: `logging.googleapis.com/user/${metricType}`,
                    },
                  },
                ],
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_Monitoring_3 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_3_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await testRule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await testRule(
        false,
        Gcp_PCI_DSS_321_Monitoring_3_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_3_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('Monitoring check 4: Logging metric filter and alert for network firewall rule changes should be configured', () => {
    const testRule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: PCIQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetrics: [
                  {
                    filter: 'dummy test filter',
                    name: 'dummy test name',
                    metricDescriptor: {
                      type: 'logging.googleapis.com/user/dummy-test-name',
                    },
                  },
                  {
                    filter,
                    name: metricName,
                    metricDescriptor: {
                      type: `logging.googleapis.com/user/${metricType}`,
                    },
                  },
                ],
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_Monitoring_4 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_4_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await testRule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await testRule(
        false,
        Gcp_PCI_DSS_321_Monitoring_4_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_4_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('Monitoring check 5: Logging metric filter and alert for network route changes should be configured', () => {
    const testRule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: PCIQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetrics: [
                  {
                    filter: 'dummy test filter',
                    name: 'dummy test name',
                    metricDescriptor: {
                      type: 'logging.googleapis.com/user/dummy-test-name',
                    },
                  },
                  {
                    filter,
                    name: metricName,
                    metricDescriptor: {
                      type: `logging.googleapis.com/user/${metricType}`,
                    },
                  },
                ],
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_Monitoring_5 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_5_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await testRule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await testRule(
        false,
        Gcp_PCI_DSS_321_Monitoring_5_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_5_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('Monitoring check 6: Logging metric filter and alert for project ownership assignments/changes should be configured', () => {
    const testRule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: PCIQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetrics: [
                  {
                    filter: 'dummy test filter',
                    name: 'dummy test name',
                    metricDescriptor: {
                      type: 'logging.googleapis.com/user/dummy-test-name',
                    },
                  },
                  {
                    filter,
                    name: metricName,
                    metricDescriptor: {
                      type: `logging.googleapis.com/user/${metricType}`,
                    },
                  },
                ],
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_Monitoring_6 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_6_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await testRule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await testRule(
        false,
        Gcp_PCI_DSS_321_Monitoring_6_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_6_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('Monitoring check 7: Logging metric filter and alert for SQL instance configuration changes should be configured', () => {
    const testRule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: PCIQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetrics: [
                  {
                    filter: 'dummy test filter',
                    name: 'dummy test name',
                    metricDescriptor: {
                      type: 'logging.googleapis.com/user/dummy-test-name',
                    },
                  },
                  {
                    filter,
                    name: metricName,
                    metricDescriptor: {
                      type: `logging.googleapis.com/user/${metricType}`,
                    },
                  },
                ],
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_Monitoring_7 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_7_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await testRule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await testRule(
        false,
        Gcp_PCI_DSS_321_Monitoring_7_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_7_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('Monitoring check 8: Logging metric filter and alert for Storage IAM permission changes should be configured', () => {
    const testRule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: PCIQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetrics: [
                  {
                    filter: 'dummy test filter',
                    name: 'dummy test name',
                    metricDescriptor: {
                      type: 'logging.googleapis.com/user/dummy-test-name',
                    },
                  },
                  {
                    filter,
                    name: metricName,
                    metricDescriptor: {
                      type: `logging.googleapis.com/user/${metricType}`,
                    },
                  },
                ],
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_Monitoring_8 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_8_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await testRule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await testRule(
        false,
        Gcp_PCI_DSS_321_Monitoring_8_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await testRule(
        true,
        Gcp_PCI_DSS_321_Monitoring_8_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })
})
