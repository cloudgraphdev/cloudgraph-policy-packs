import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_NIST_800_53_51 from '../rules/gcp-nist-800-53-rev4-5.1'
import Gcp_NIST_800_53_52 from '../rules/gcp-nist-800-53-rev4-5.2'
import Gcp_NIST_800_53_53 from '../rules/gcp-nist-800-53-rev4-5.3'
import Gcp_NIST_800_53_54 from '../rules/gcp-nist-800-53-rev4-5.4'
import Gcp_NIST_800_53_55 from '../rules/gcp-nist-800-53-rev4-5.5'
import Gcp_NIST_800_53_56 from '../rules/gcp-nist-800-53-rev4-5.6'
import Gcp_NIST_800_53_57 from '../rules/gcp-nist-800-53-rev4-5.7'
import Gcp_NIST_800_53_58 from '../rules/gcp-nist-800-53-rev4-5.8'

const Gcp_NIST_800_53_51_Filter =
  '( protoPayload.serviceName="cloudresourcemanager.googleapis.com" ) AND ( ProjectOwnership OR projectOwnerInvitee ) OR ( protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner" ) OR ( protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner" )'
const Gcp_NIST_800_53_52_Filter =
  'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*'
const Gcp_NIST_800_53_53_Filter =
  'resource.type="iam_role" AND protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole"'
const Gcp_NIST_800_53_54_Filter =
  'resource.type="gce_firewall_rule" AND protoPayload.methodName="v1.compute.firewalls.patch" OR protoPayload.methodName="v1.compute.firewalls.insert"'
const Gcp_NIST_800_53_55_Filter =
  'resource.type="gce_route" AND protoPayload.methodName="beta.compute.routes.patch" OR protoPayload.methodName="beta.compute.routes.insert"'
const Gcp_NIST_800_53_56_Filter =
  'resource.type=gce_network AND protoPayload.methodName="beta.compute.networks.insert" OR protoPayload.methodName="beta.compute.networks.patch" OR protoPayload.methodName="v1.compute.networks.delete" OR protoPayload.methodName="v1.compute.networks.removePeering" OR protoPayload.methodName="v1.compute.networks.addPeering"'
const Gcp_NIST_800_53_57_Filter =
  'protoPayload.methodName="cloudsql.instances.update"'

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

export interface NIST5xQueryResponse {
  querygcpAlertPolicy?: QuerygcpAlertPolicy[]
  querygcpNetwork?: QuerygcpNetwork[]
  querygcpProject?: QuerygcpProject[]
  querygcpIamPolicy?: QuerygcpIamPolicy[]
}

describe('GCP NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'NIST'} )
  })

  describe('GCP NIST 5.1 Logging metric filter and alert for project ownership assignments/changes should be configured', () => {
    const testRule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: NIST5xQueryResponse = {
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
        Gcp_NIST_800_53_51 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await testRule(
        true,
        Gcp_NIST_800_53_51_Filter,
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
        Gcp_NIST_800_53_51_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await testRule(
        true,
        Gcp_NIST_800_53_51_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('GCP NIST 5.2 Logging metric filter and alert for audit configuration changes should be configured', () => {
    const testRule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: NIST5xQueryResponse = {
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
        Gcp_NIST_800_53_52 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await testRule(
        true,
        Gcp_NIST_800_53_52_Filter,
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
        Gcp_NIST_800_53_52_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await testRule(
        true,
        Gcp_NIST_800_53_52_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('GCP NIST 5.3 Logging metric filter and alert for Custom Role changes should be configured', () => {
    const testRule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: NIST5xQueryResponse = {
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
        Gcp_NIST_800_53_53 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await testRule(
        true,
        Gcp_NIST_800_53_53_Filter,
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
        Gcp_NIST_800_53_53_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await testRule(
        true,
        Gcp_NIST_800_53_53_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('GCP NIST 5.4 Logging metric filter and alert for network firewall rule changes should be configured', () => {
    const testRule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: NIST5xQueryResponse = {
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
        Gcp_NIST_800_53_54 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await testRule(
        true,
        Gcp_NIST_800_53_54_Filter,
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
        Gcp_NIST_800_53_54_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await testRule(
        true,
        Gcp_NIST_800_53_54_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('GCP NIST 5.5 Logging metric filter and alert for network route changes should be configured', () => {
    const testRule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: NIST5xQueryResponse = {
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
        Gcp_NIST_800_53_55 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await testRule(
        true,
        Gcp_NIST_800_53_55_Filter,
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
        Gcp_NIST_800_53_55_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await testRule(
        true,
        Gcp_NIST_800_53_55_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('GCP NIST 5.6 Logging metric filter and alert for network changes should be configured', () => {
    const testRule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: NIST5xQueryResponse = {
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
        Gcp_NIST_800_53_56 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await testRule(
        true,
        Gcp_NIST_800_53_56_Filter,
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
        Gcp_NIST_800_53_56_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await testRule(
        true,
        Gcp_NIST_800_53_56_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('GCP NIST 5.7 Logging metric filter and alert for SQL instance configuration changes should be configured', () => {
    const testRule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: NIST5xQueryResponse = {
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
        Gcp_NIST_800_53_57 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await testRule(
        true,
        Gcp_NIST_800_53_57_Filter,
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
        Gcp_NIST_800_53_57_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await testRule(
        true,
        Gcp_NIST_800_53_57_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('GCP NIST 5.8 Logging storage bucket retention policies and Bucket Lock should be configured', () => {
    const getTestRuleFixture = (
      querygcpProjects: QuerygcpProject[]
    ): NIST5xQueryResponse => {
      return {
        querygcpProject: querygcpProjects,
      }
    }

    const testRule = async (
      data: NIST5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_58 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when all Sinks destined to storage buckets have retention policies and Bucket Lock are enabled', async () => {
      const projectData = [
        {
          id: cuid(),
          logSinks: [
            {
              destination: 'logging.googleapis.com/projects/dummy',
            },
            {
              destination: 'storage.googleapis.com/projects/storage-project',
            },
          ],
          logBuckets: [
            {
              name: 'projects/dummy',
              retentionDays: 30,
              locked: false,
            },
            {
              name: 'projects/storage-project',
              retentionDays: 30,
              locked: true,
            },
          ],
        },
      ]
      const data: NIST5xQueryResponse = getTestRuleFixture(projectData)
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when all Sinks destined to storage buckets have retention policies and Bucket Lock are enabled (multiple sinks)', async () => {
      const projectData = [
        {
          id: cuid(),
          logSinks: [
            {
              destination: 'storage.googleapis.com/projects/storage-project',
            },
            {
              destination: 'storage.googleapis.com/projects/storage-project2',
            },
          ],
          logBuckets: [
            {
              name: 'projects/storage-project',
              retentionDays: 30,
              locked: true,
            },
            {
              name: 'projects/storage-project2',
              retentionDays: 30,
              locked: true,
            },
          ],
        },
      ]
      const data: NIST5xQueryResponse = getTestRuleFixture(projectData)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when no Sinks destined to storage buckets', async () => {
      const projectData = [
        {
          id: cuid(),
          logSinks: [
            {
              destination: 'storage.googleapis.com/projects/storage-project',
            },
          ],
          logBuckets: [],
        },
      ]
      const data: NIST5xQueryResponse = getTestRuleFixture(projectData)
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when the Sinks destined to storage buckets have NO retention policies', async () => {
      const projectData = [
        {
          id: cuid(),
          logSinks: [
            {
              destination: 'storage.googleapis.com/projects/storage-project',
            },
          ],
          logBuckets: [
            {
              name: 'projects/storage-project',
              retentionDays: 0,
              locked: true,
            },
          ],
        },
      ]
      const data: NIST5xQueryResponse = getTestRuleFixture(projectData)
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when the Sinks destined to storage buckets have Bucket Lock set to false', async () => {
      const projectData = [
        {
          id: cuid(),
          logSinks: [
            {
              destination: 'storage.googleapis.com/projects/storage-project',
            },
          ],
          logBuckets: [
            {
              name: 'projects/storage-project',
              retentionDays: 30,
              locked: false,
            },
          ],
        },
      ]
      const data: NIST5xQueryResponse = getTestRuleFixture(projectData)
      await testRule(data, Result.FAIL)
    })
  })

})
