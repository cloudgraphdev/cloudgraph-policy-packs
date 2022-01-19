/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Gcp_CIS_120_22 from '../rules/gcp-cis-1.2.0-2.2'
import Gcp_CIS_120_23 from '../rules/gcp-cis-1.2.0-2.3'
import Gcp_CIS_120_24 from '../rules/gcp-cis-1.2.0-2.4'
import Gcp_CIS_120_25 from '../rules/gcp-cis-1.2.0-2.5'
import Gcp_CIS_120_26 from '../rules/gcp-cis-1.2.0-2.6'
import Gcp_CIS_120_27 from '../rules/gcp-cis-1.2.0-2.7'
import Gcp_CIS_120_28 from '../rules/gcp-cis-1.2.0-2.8'
import Gcp_CIS_120_29 from '../rules/gcp-cis-1.2.0-2.9'
import Gcp_CIS_120_210 from '../rules/gcp-cis-1.2.0-2.10'
import Gcp_CIS_120_211 from '../rules/gcp-cis-1.2.0-2.11'
import Gcp_CIS_120_212 from '../rules/gcp-cis-1.2.0-2.12'

const Gcp_CIS_120_24_Filter =
  '( protoPayload.serviceName="cloudresourcemanager.googleapis.com" ) AND ( ProjectOwnership OR projectOwnerInvitee ) OR ( protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner" ) OR ( protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner" )'
const Gcp_CIS_120_25_Filter =
  'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*'
const Gcp_CIS_120_26_Filter =
  'resource.type="iam_role" AND protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole"'
const Gcp_CIS_120_27_Filter =
  'resource.type="gce_firewall_rule" AND protoPayload.methodName="v1.compute.firewalls.patch" OR protoPayload.methodName="v1.compute.firewalls.insert"'
const Gcp_CIS_120_28_Filter =
  'resource.type="gce_route" AND protoPayload.methodName="beta.compute.routes.patch" OR protoPayload.methodName="beta.compute.routes.insert"'
const Gcp_CIS_120_29_Filter =
  'resource.type=gce_network AND protoPayload.methodName="beta.compute.networks.insert" OR protoPayload.methodName="beta.compute.networks.patch" OR protoPayload.methodName="v1.compute.networks.delete" OR protoPayload.methodName="v1.compute.networks.removePeering" OR protoPayload.methodName="v1.compute.networks.addPeering"'
const Gcp_CIS_120_210_Filter =
  'resource.type=gcs_bucket AND protoPayload.methodName="storage.setIamPermissions"'
const Gcp_CIS_120_211_Filter =
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
  logMetric?: LogMetric[]
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
  dnsPolicy?: DnsPolicy[]
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
  logSink: LogSink[]
  logBucket?: LogBucket[]
}

export interface CIS2xQueryResponse {
  querygcpAlertPolicy?: QuerygcpAlertPolicy[]
  querygcpNetwork?: QuerygcpNetwork[]
  querygcpProject?: QuerygcpProject[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine('gcp', 'CIS')
  })

  describe('GCP CIS 2.2 Ensure that sinks are configured for all log entries', () => {
    const getTest22RuleFixture = (filter: string): CIS2xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            logSink: [
              {
                filter: 'dummy filter',
              },
              {
                filter,
              },
            ],
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
        Gcp_CIS_120_22 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is a logSink with an empty filter', async () => {
      const data: CIS2xQueryResponse = getTest22RuleFixture('')
      await test22Rule(data, Result.PASS)
    })

    test('Security Issue when there is a logSink with an empty filter', async () => {
      const data: CIS2xQueryResponse = getTest22RuleFixture('dummy-filter')
      await test22Rule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 2.3 Ensure that retention policies on log buckets are configured using Bucket Lock', () => {
    const getTest23RuleFixture = (
      querygcpProjects: QuerygcpProject[]
    ): CIS2xQueryResponse => {
      return {
        querygcpProject: querygcpProjects,
      }
    }

    const test23Rule = async (
      data: CIS2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_23 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when all Sinks destined to storage buckets have retention policies and Bucket Lock are enabled', async () => {
      const projectData = [
        {
          id: cuid(),
          logSink: [
            {
              destination: 'logging.googleapis.com/projects/dummy',
            },
            {
              destination: 'storage.googleapis.com/projects/storage-project',
            },
          ],
          logBucket: [
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
      const data: CIS2xQueryResponse = getTest23RuleFixture(projectData)
      await test23Rule(data, Result.PASS)
    })

    test('No Security Issue when all Sinks destined to storage buckets have retention policies and Bucket Lock are enabled (multiple sinks)', async () => {
      const projectData = [
        {
          id: cuid(),
          logSink: [
            {
              destination: 'storage.googleapis.com/projects/storage-project',
            },
            {
              destination: 'storage.googleapis.com/projects/storage-project2',
            },
          ],
          logBucket: [
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
      const data: CIS2xQueryResponse = getTest23RuleFixture(projectData)
      await test23Rule(data, Result.PASS)
    })

    test('Security Issue when no Sinks destined to storage buckets', async () => {
      const projectData = [
        {
          id: cuid(),
          logSink: [
            {
              destination: 'storage.googleapis.com/projects/storage-project',
            },
          ],
          logBucket: [],
        },
      ]
      const data: CIS2xQueryResponse = getTest23RuleFixture(projectData)
      await test23Rule(data, Result.FAIL)
    })

    test('Security Issue when the Sinks destined to storage buckets have NO retention policies', async () => {
      const projectData = [
        {
          id: cuid(),
          logSink: [
            {
              destination: 'storage.googleapis.com/projects/storage-project',
            },
          ],
          logBucket: [
            {
              name: 'projects/storage-project',
              retentionDays: 0,
              locked: true,
            },
          ],
        },
      ]
      const data: CIS2xQueryResponse = getTest23RuleFixture(projectData)
      await test23Rule(data, Result.FAIL)
    })

    test('Security Issue when the Sinks destined to storage buckets have Bucket Lock set to false', async () => {
      const projectData = [
        {
          id: cuid(),
          logSink: [
            {
              destination: 'storage.googleapis.com/projects/storage-project',
            },
          ],
          logBucket: [
            {
              name: 'projects/storage-project',
              retentionDays: 30,
              locked: false,
            },
          ],
        },
      ]
      const data: CIS2xQueryResponse = getTest23RuleFixture(projectData)
      await test23Rule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 2.4 Ensure log metric filter and alerts exist for Audit Configuration Changes', () => {
    const test24Rule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS2xQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetric: [
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
        Gcp_CIS_120_24 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await test24Rule(
        true,
        Gcp_CIS_120_24_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await test24Rule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await test24Rule(
        false,
        Gcp_CIS_120_24_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await test24Rule(
        true,
        Gcp_CIS_120_24_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('GCP CIS 2.5 Ensure that the log metric filter and alerts exist for Audit Configuration changes', () => {
    const test25Rule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS2xQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetric: [
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
        Gcp_CIS_120_25 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await test25Rule(
        true,
        Gcp_CIS_120_25_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await test25Rule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await test25Rule(
        false,
        Gcp_CIS_120_25_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await test25Rule(
        true,
        Gcp_CIS_120_25_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('GCP CIS 2.6 Ensure that the log metric filter and alerts exist for Custom Role changes', () => {
    const test26Rule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS2xQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetric: [
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
        Gcp_CIS_120_26 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await test26Rule(
        true,
        Gcp_CIS_120_26_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await test26Rule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await test26Rule(
        false,
        Gcp_CIS_120_26_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await test26Rule(
        true,
        Gcp_CIS_120_26_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('GCP CIS 2.7 Ensure that the log metric filter and alerts exist for VPC Network Firewall rule changes', () => {
    const test27Rule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS2xQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetric: [
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
        Gcp_CIS_120_27 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await test27Rule(
        true,
        Gcp_CIS_120_27_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await test27Rule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await test27Rule(
        false,
        Gcp_CIS_120_27_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await test27Rule(
        true,
        Gcp_CIS_120_27_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('GCP CIS 2.8 Ensure that the log metric filter and alerts exist for VPC network route changes', () => {
    const test28Rule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS2xQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetric: [
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
        Gcp_CIS_120_28 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await test28Rule(
        true,
        Gcp_CIS_120_28_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await test28Rule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await test28Rule(
        false,
        Gcp_CIS_120_28_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await test28Rule(
        true,
        Gcp_CIS_120_28_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('GCP CIS 2.9 Ensure that the log metric filter and alerts exist for VPC network changes', () => {
    const test29Rule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS2xQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetric: [
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
        Gcp_CIS_120_29 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await test29Rule(
        true,
        Gcp_CIS_120_29_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await test29Rule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await test29Rule(
        false,
        Gcp_CIS_120_29_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await test29Rule(
        true,
        Gcp_CIS_120_29_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('GCP CIS 2.10 Ensure that the log metric filter and alerts exist for Cloud Storage IAM permission changes', () => {
    const test210Rule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS2xQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetric: [
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
        Gcp_CIS_120_210 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await test210Rule(
        true,
        Gcp_CIS_120_210_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await test210Rule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await test210Rule(
        false,
        Gcp_CIS_120_210_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await test210Rule(
        true,
        Gcp_CIS_120_210_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('GCP CIS 2.11 Ensure that the log metric filter and alerts exist for SQL instance configuration changes', () => {
    const test211Rule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS2xQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled,
            },
            project: [
              {
                logMetric: [
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
        Gcp_CIS_120_211 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alerts exist', async () => {
      await test211Rule(
        true,
        Gcp_CIS_120_211_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.PASS
      )
    })

    test('Security Issue when there metric filters is not found', async () => {
      await test211Rule(
        true,
        'dummy metric filter value',
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await test211Rule(
        false,
        Gcp_CIS_120_211_Filter,
        'log-metric-1',
        'log-metric-1',
        Result.FAIL
      )
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await test211Rule(
        true,
        Gcp_CIS_120_211_Filter,
        'log-metric-1',
        'log-metric-2',
        Result.FAIL
      )
    })
  })

  describe('GCP CIS 2.12 Ensure that Cloud DNS logging is enabled for all VPC networks', () => {
    const test212Rule = async (
      enableLogging: boolean,
      emptyPolicy: boolean,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS2xQueryResponse = {
        querygcpNetwork: [
          {
            id: cuid(),
            dnsPolicy: [
              {
                enableLogging,
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_212 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with dns logging enabled for all VPC networks', async () => {
      await test212Rule(true, false, Result.PASS)
    })

    test('Security Issue when there is an inbound rule that does not have dns logging enabled for all VPC networks', async () => {
      await test212Rule(false, false, Result.FAIL)
    })
  })
})
