import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Azure_PCI_DSS_321_Monitoring_1 from '../rules/pci-dss-3.2.1-monitoring-check-1'
import Azure_PCI_DSS_321_Monitoring_2 from '../rules/pci-dss-3.2.1-monitoring-check-2'
import Azure_PCI_DSS_321_Monitoring_3 from '../rules/pci-dss-3.2.1-monitoring-check-3'
import Azure_PCI_DSS_321_Monitoring_4 from '../rules/pci-dss-3.2.1-monitoring-check-4'
import Azure_PCI_DSS_321_Monitoring_5 from '../rules/pci-dss-3.2.1-monitoring-check-5'
import Azure_PCI_DSS_321_Monitoring_6 from '../rules/pci-dss-3.2.1-monitoring-check-6'
import Azure_PCI_DSS_321_Monitoring_7 from '../rules/pci-dss-3.2.1-monitoring-check-7'
import Azure_PCI_DSS_321_Monitoring_8 from '../rules/pci-dss-3.2.1-monitoring-check-8'
import Azure_PCI_DSS_321_Monitoring_9 from '../rules/pci-dss-3.2.1-monitoring-check-9'
import Azure_PCI_DSS_321_Monitoring_10 from '../rules/pci-dss-3.2.1-monitoring-check-10'
import Azure_PCI_DSS_321_Monitoring_11 from '../rules/pci-dss-3.2.1-monitoring-check-11'
import Azure_PCI_DSS_321_Monitoring_12 from '../rules/pci-dss-3.2.1-monitoring-check-12'

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

export interface PCIQueryResponse {
  queryazureLogProfile?: QueryazureLogProfile[]
  queryazureSubscription?: QueryazureSubscription[]
  queryazurePolicyAssignment?: QueryazurePolicyAssignment[]
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

  describe('Monitoring Check 5: Monitor Activity Log Alert should exist for Create or Update Network Security Group', () => {
    const getTestRuleFixture_525 = (
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

    const testRule = async (
      rulesEngine: Engine,
      data: any,
      rule: Rule,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(rule as Rule, {
        ...data,
      })
      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Create or Update Network Security Group Rule', async () => {
      const data: PCIQueryResponse = getTestRuleFixture_525(
        true,
        'operationName',
        'microsoft.network/networksecuritygroups/securityrules/write'
      )

      await testRule(rulesEngine, data, Azure_PCI_DSS_321_Monitoring_5 as Rule, Result.PASS)
    })

    test('Security Issue when Activity Log Alert doesnt exist for Create or Update Network Security Group Rule', async () => {
      const data: PCIQueryResponse = getTestRuleFixture_525(
        true,
        '',
        ''
      )

      await testRule(rulesEngine, data, Azure_PCI_DSS_321_Monitoring_5 as Rule, Result.FAIL)
    })
  })

  describe('Monitoring Check 6: Monitor Activity Log Alert should exist for Create or Update Network Security Group Rule', () => {
    const getTestRuleFixture = (
      enabled: boolean,
      field: string,
      equals: string,
    ): PCIQueryResponse => {
      return {
        queryazureSubscription: [
          {
            id: cuid(),
            activityLogAlerts: [{
              id: cuid(),
              enabled,
              condition: {
                allOf: [{
                  id: cuid(),
                  field,
                  equals,
                }]
              },
            }],
          },
        ],
      }
    }

    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Monitoring_6 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Create or Update or Delete SQL Server Firewall Rule', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, 'operationName', 'Microsoft.Network/networkSecurityGroups/securityRules/write')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Activity Log Alert doesnt exist for Create or Update or Delete SQL Server Firewall Rule', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, '', '')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Monitoring Check 7: Monitor Activity Log Alert should exist for Create or Update or Delete SQL Server Firewall Rule', () => {
    const getTestRuleFixture = (
      enabled: boolean,
      field: string,
      equals: string,
    ): PCIQueryResponse => {
      return {
        queryazureSubscription: [
          {
            id: cuid(),
            activityLogAlerts: [{
              id: cuid(),
              enabled,
              condition: {
                allOf: [{
                  id: cuid(),
                  field,
                  equals,
                }]
              },
            }],
          },
        ],
      }
    }

    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Monitoring_7 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Create or Update or Delete SQL Server Firewall Rule', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, 'operationName', 'microsoft.sql/servers/firewallrules/write')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Activity Log Alert doesnt exist for Create or Update or Delete SQL Server Firewall Rule', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, '', '')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Monitoring Check 8: Monitor Activity Log Alert should exist for Create or Update Security Solution', () => {
    const getTestRuleFixture = (
      enabled: boolean,
      field: string,
      equals: string,
    ): PCIQueryResponse => {
      return {
        queryazureSubscription: [
          {
            id: cuid(),
            activityLogAlerts: [{
              id: cuid(),
              enabled,
              condition: {
                allOf: [{
                  id: cuid(),
                  field,
                  equals,
                }]
              },
            }],
          },
        ],
      }
    }

    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Monitoring_8 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Create or Update Security Solution', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, 'operationName', 'microsoft.security/securitysolutions/write')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Activity Log Alert doesnt exist for Create or Update Security Solution', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, '', '')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Monitoring Check 9: Monitor Activity Log Alert should exist for Create Policy Assignment', () => {
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

    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Monitoring_9 as Rule, {
        ...data,
      })
      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Create Policy Assignment', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        true,
        'operationName',
        'microsoft.authorization/policyassignments/write'
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when Activity Log Alert doesnt exist for Create Policy Assignment', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        true,
        '',
        ''
      )

      await testRule(data, Result.FAIL)
    })
  })

  describe('Monitoring Check 10: Monitor Activity Log Alert should exist for Delete Network Security Group', () => {
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

    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Monitoring_10 as Rule, {
        ...data,
      })
      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Delete Network Security Group', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        true,
        'operationName',
        'microsoft.network/networksecuritygroups/delete'
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when Activity Log Alert doesnt exist for Delete Network Security Group', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        true,
        '',
        ''
      )

      await testRule(data, Result.FAIL)
    })
  })

  describe('Monitoring Check 11: Monitor Activity Log Alert should exist for Delete Network Security Group Rule', () => {
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

    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Monitoring_11 as Rule, {
        ...data,
      })
      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for the Delete Network Security Group Rule', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        true,
        'operationName',
        'microsoft.network/networksecuritygroups/securityrules/delete'
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when Activity Log Alert doesnt exist for the Delete Network Security Group Rule', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        true,
        '',
        ''
      )

      await testRule(data, Result.FAIL)
    })
  })

  describe('Monitoring Check 12: Monitor Activity Log Alert should exist for Delete Security Solution', () => {
    const getTestRuleFixture = (
      enabled: boolean,
      field: string,
      equals: string,
    ): PCIQueryResponse => {
      return {
        queryazureSubscription: [
          {
            id: cuid(),
            activityLogAlerts: [{
              id: cuid(),
              enabled,
              condition: {
                allOf: [{
                  id: cuid(),
                  field,
                  equals,
                }]
              },
            }],
          },
        ],
      }
    }

    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Monitoring_12 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Delete Security Solution', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, 'operationName', 'microsoft.security/securitysolutions/delete')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Activity Log Alert doesnt exist for Delete Security Solution', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(true, '', '')

      await testRule(data, Result.FAIL)
    })
  })
})
