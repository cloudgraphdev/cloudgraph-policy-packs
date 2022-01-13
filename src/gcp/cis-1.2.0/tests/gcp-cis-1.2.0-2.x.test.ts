/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Gcp_CIS_120_29 from '../rules/gcp-cis-1.2.0-2.9'
import Gcp_CIS_120_210 from '../rules/gcp-cis-1.2.0-2.10'
import Gcp_CIS_120_211 from '../rules/gcp-cis-1.2.0-2.11'
import Gcp_CIS_120_212 from '../rules/gcp-cis-1.2.0-2.12'

const Gcp_CIS_120_29_Filter = 'resource.type=gce_network AND protoPayload.methodName="beta.compute.networks.insert" OR protoPayload.methodName="beta.compute.networks.patch" OR protoPayload.methodName="v1.compute.networks.delete" OR protoPayload.methodName="v1.compute.networks.removePeering" OR protoPayload.methodName="v1.compute.networks.addPeering"'
const Gcp_CIS_120_210_Filter = 'resource.type=gcs_bucket AND protoPayload.methodName="storage.setIamPermissions"'
const Gcp_CIS_120_211_Filter = 'protoPayload.methodName="cloudsql.instances.update"'

export interface MetricDescriptor {
  type: string,
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

export interface CIS2xQueryResponse {
  querygcpAlertPolicy?: QuerygcpAlertPolicy[]
  querygcpNetwork?: QuerygcpNetwork[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine('gcp', 'CIS')
  })
  describe('GCP CIS 2.9 Ensure that the log metric filter and alerts exist for VPC network changes', () => {
    const test29Rule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result,
    ): Promise<void> => {
      // Arrange
      const data: CIS2xQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled
            },
            project: [
              {
                logMetric: [
                  {
                    filter: 'dummy test filter',
                    name: 'dummy test name',
                    metricDescriptor: {
                      type: 'logging.googleapis.com/user/dummy-test-name'
                    }
                  },
                  {
                    filter,
                    name: metricName,
                    metricDescriptor: {
                      type: `logging.googleapis.com/user/${metricType}`
                    }
                  }
                ]
              }
            ]
          }
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
      await test29Rule(true, Gcp_CIS_120_29_Filter, 'log-metric-1', 'log-metric-1', Result.PASS)
    })

    test('Security Issue when there metric filters is not found', async () => {
      await test29Rule(true, 'dummy metric filter value', 'log-metric-1', 'log-metric-1', Result.FAIL)
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await test29Rule(false, Gcp_CIS_120_29_Filter, 'log-metric-1', 'log-metric-1', Result.FAIL)
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await test29Rule(true, Gcp_CIS_120_29_Filter, 'log-metric-1', 'log-metric-2', Result.FAIL)
    })
  })

  describe('GCP CIS 2.10 Ensure that the log metric filter and alerts exist for Cloud Storage IAM permission changes', () => {
    const test210Rule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result,
    ): Promise<void> => {
      // Arrange
      const data: CIS2xQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled
            },
            project: [
              {
                logMetric: [
                  {
                    filter: 'dummy test filter',
                    name: 'dummy test name',
                    metricDescriptor: {
                      type: 'logging.googleapis.com/user/dummy-test-name'
                    }
                  },
                  {
                    filter,
                    name: metricName,
                    metricDescriptor: {
                      type: `logging.googleapis.com/user/${metricType}`
                    }
                  }
                ]
              }
            ]
          }
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
      await test210Rule(true, Gcp_CIS_120_210_Filter, 'log-metric-1', 'log-metric-1', Result.PASS)
    })

    test('Security Issue when there metric filters is not found', async () => {
      await test210Rule(true, 'dummy metric filter value', 'log-metric-1', 'log-metric-1', Result.FAIL)
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await test210Rule(false, Gcp_CIS_120_210_Filter, 'log-metric-1', 'log-metric-1', Result.FAIL)
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await test210Rule(true, Gcp_CIS_120_210_Filter, 'log-metric-1', 'log-metric-2', Result.FAIL)
    })
  })

  describe('GCP CIS 2.11 Ensure that the log metric filter and alerts exist for SQL instance configuration changes', () => {
    const test211Rule = async (
      enabled: boolean,
      filter: string,
      metricName: string,
      metricType: string,
      expectedResult: Result,
    ): Promise<void> => {
      // Arrange
      const data: CIS2xQueryResponse = {
        querygcpAlertPolicy: [
          {
            id: cuid(),
            enabled: {
              value: enabled
            },
            project: [
              {
                logMetric: [
                  {
                    filter: 'dummy test filter',
                    name: 'dummy test name',
                    metricDescriptor: {
                      type: 'logging.googleapis.com/user/dummy-test-name'
                    }
                  },
                  {
                    filter,
                    name: metricName,
                    metricDescriptor: {
                      type: `logging.googleapis.com/user/${metricType}`
                    }
                  }
                ]
              }
            ]
          }
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
      await test211Rule(true, Gcp_CIS_120_211_Filter, 'log-metric-1', 'log-metric-1', Result.PASS)
    })

    test('Security Issue when there metric filters is not found', async () => {
      await test211Rule(true, 'dummy metric filter value', 'log-metric-1', 'log-metric-1', Result.FAIL)
    })

    test('Security Issue when there are metric filters but not aletrs', async () => {
      await test211Rule(false, Gcp_CIS_120_211_Filter, 'log-metric-1', 'log-metric-1', Result.FAIL)
    })

    test('Security Issue when there are metric filters and aletrs but metric desciptor type not match with metric name', async () => {
      await test211Rule(true, Gcp_CIS_120_211_Filter, 'log-metric-1', 'log-metric-2', Result.FAIL)
    })
  })

  describe('GCP CIS 2.12 Ensure that Cloud DNS logging is enabled for all VPC networks', () => {
    const test212Rule = async (
      enableLogging: boolean,
      emptyPolicy: boolean,
      expectedResult: Result,
    ): Promise<void> => {
      // Arrange
      const data: CIS2xQueryResponse = {
        querygcpNetwork: [
          {
            id: cuid(),
            dnsPolicy: [ 
              { 
                enableLogging 
              }
            ]
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