import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Azure_PCI_DSS_321_Monitoring_1 from '../rules/pci-dss-3.2.1-monitoring-check-1'
import Azure_PCI_DSS_321_Monitoring_2 from '../rules/pci-dss-3.2.1-monitoring-check-2'
import Azure_PCI_DSS_321_Monitoring_3 from '../rules/pci-dss-3.2.1-monitoring-check-3'
import Azure_PCI_DSS_321_Monitoring_4 from '../rules/pci-dss-3.2.1-monitoring-check-4'
import Azure_PCI_DSS_321_Monitoring_14 from '../rules/pci-dss-3.2.1-monitoring-check-14'

export interface azureActivityLogAlertLeafCondition {
  id: string
  field: string
  equals: string
}

export interface azureActivityLogAlertAllOfCondition {
  allOf: [azureActivityLogAlertLeafCondition]
}

export interface QueryazureActivityLogAlert {
  id: string
  region?: string
  enabled?: boolean
  condition?: azureActivityLogAlertAllOfCondition
}

export interface QueryazureSubscription {
  id: string
  activityLogAlerts: QueryazureActivityLogAlert[]
}

export interface RetentionPolicy {
  enabled: boolean
  days: number
}
export interface QueryazureLogProfile {
  id: string
  categories?: string[]
  retentionPolicy?: RetentionPolicy | null
}

export interface KeyValue {
  key: string
  value: string
}

export interface Parameter {
  key: string
  value: KeyValue[]
}

export interface QueryazurePolicyAssignment {
  id: string
  displayName: string
  parameters: Parameter[]
}
export interface ServerBlobAuditingPolicy {
  state: string
}
export interface QueryazureSqlServer {
  id: string
  serverBlobAuditingPolicies: ServerBlobAuditingPolicy[]
}
export interface PCIQueryResponse {
  queryazureLogProfile?: QueryazureLogProfile[]
  queryazureSubscription?: QueryazureSubscription[]
  queryazurePolicyAssignment?: QueryazurePolicyAssignment[]
  queryazureSqlServer?: QueryazureSqlServer[]
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'PCI')
  })

  describe('Monitoring Check 1: Monitor audit profile should log all activities', () => {
    const getTestRuleFixture = (categories: string[]): PCIQueryResponse => {
      return {
        queryazureLogProfile: [
          {
            id: cuid(),
            categories,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Monitoring_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Monitor audit profile log all activities', async () => {
      const data: PCIQueryResponse = getTestRuleFixture([
        'Action',
        'Write',
        'Delete',
      ])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when Monitor audit profile not log all activities', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(['Action', 'Delete'])
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when Monitor audit profile log activities are empty', async () => {
      const data: PCIQueryResponse = getTestRuleFixture([])
      await testRule(data, Result.FAIL)
    })
  })

  describe('Monitoring Check 2: Monitor Activity Log Alert should exist for Update Security Policy', () => {
    const getTestRuleFixture = (
      enabled: boolean,
      field: string,
      equals: string
    ): PCIQueryResponse => {
      return {
        queryazureSubscription: [
          {
            id: cuid(),
            activityLogAlerts: [
              {
                id: cuid(),
                enabled,
                condition: {
                  allOf: [
                    {
                      id: cuid(),
                      field,
                      equals,
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Monitoring_2 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Create Policy Assignment', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        true,
        'operationName',
        'Microsoft.Security/policies/write'
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when Activity Log Alert doesnt exist for Create Policy Assignment', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, '', '')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Monitoring Check 3: Security Center default policy setting ‘Monitor Endpoint Protection’ should be enabled', () => {
    const getTestRuleFixture = (
      displayName: string,
      parameters: Parameter[]
    ): PCIQueryResponse => {
      return {
        queryazurePolicyAssignment: [
          {
            id: cuid(),
            displayName,
            parameters,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Monitoring_3 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ‘Monitor Endpoint Protection’ is enabled', async () => {
      const parameters = [
        {
          key: 'effect',
          value: [
            {
              key: 'effect',
              value: 'A',
            },
            {
              key: 'effect',
              value: 'u',
            },
            {
              key: 'effect',
              value: 'd',
            },
            {
              key: 'effect',
              value: 'i',
            },
            {
              key: 'effect',
              value: 't',
            },
            {
              key: 'effect',
              value: 'I',
            },
            {
              key: 'effect',
              value: 'f',
            },
            {
              key: 'effect',
              value: 'N',
            },
            {
              key: 'effect',
              value: 'o',
            },
            {
              key: 'effect',
              value: 't',
            },
            {
              key: 'effect',
              value: 'E',
            },
            {
              key: 'effect',
              value: 'x',
            },
            {
              key: 'effect',
              value: 'i',
            },
            {
              key: 'effect',
              value: 's',
            },
            {
              key: 'effect',
              value: 't',
            },
            {
              key: 'effect',
              value: 's',
            },
          ],
        },
      ]

      const data: PCIQueryResponse = getTestRuleFixture(
        'Monitor missing Endpoint Protection in Azure Security Center',
        parameters
      )

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when definition is not ‘Monitor Endpoint Protection’', async () => {

      const data: PCIQueryResponse = getTestRuleFixture(
        'Defender for Containers provisioning AKS Security Profile',
        []
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when  ‘Monitor Endpoint Protection’ is not enabled', async () => {

      const data: PCIQueryResponse = getTestRuleFixture(
        'Monitor missing Endpoint Protection in Azure Security Center',
        []
      )

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when ‘Monitor Endpoint Protection’ not have set the parameter ‘AuditIfNotExists’', async () => {
      const parameters = [
        {
          key: 'effect',
          value: [
            {
              key: 'effect',
              value: 'T',
            },
            {
              key: 'effect',
              value: 'e',
            },
            {
              key: 'effect',
              value: 's',
            },
            {
              key: 'effect',
              value: 't',
            },
          ],
        },
      ]

      const data: PCIQueryResponse = getTestRuleFixture(
        'Monitor missing Endpoint Protection in Azure Security Center',
        parameters
      )

      await testRule(data, Result.FAIL)
    })
  })

  describe('Monitoring Check 4: Monitor log profile should be created', () => {
    const getTestRuleFixture = (
      enabled: boolean,
      days: number,
    ): PCIQueryResponse => {
      return {
        queryazureLogProfile: [
          {
            id: cuid(),
            retentionPolicy: {
              enabled,
              days,
            },
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Monitoring_4 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Monitor audit profile log is created', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, 0)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when Monitor audit profile log is not created', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(false, 0)
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when Monitor audit profile log is empty', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(false, 0)
      const logProfile = data.queryazureLogProfile?.[0] as QueryazureLogProfile
      logProfile.retentionPolicy = null
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when Monitor audit profile is not set to retain the events indefinitely', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, 7)
      await testRule(data, Result.FAIL)
    })
  })

  describe('Monitoring Check 14: SQL Server auditing should be enabled', () => {
    const getTestRuleFixture = (
      state: string
      ): PCIQueryResponse => {
      return {
        queryazureSqlServer: [
          {
            id: cuid(),
            serverBlobAuditingPolicies: [
              {
                state
              }
            ]
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Monitoring_14 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when SQL Server auditing is enabled', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Enabled')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when SQL Server auditing is disabled', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('Disabled')
      await testRule(data, Result.FAIL)
    })
  })
})
