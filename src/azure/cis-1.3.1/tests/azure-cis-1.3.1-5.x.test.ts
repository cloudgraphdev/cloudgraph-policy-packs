/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_CIS_131_521 from '../rules/azure-cis-1.3.1-5.2.1'
import Azure_CIS_131_522 from '../rules/azure-cis-1.3.1-5.2.2'
import Azure_CIS_131_523 from '../rules/azure-cis-1.3.1-5.2.3'
import Azure_CIS_131_524 from '../rules/azure-cis-1.3.1-5.2.4'
import Azure_CIS_131_525 from '../rules/azure-cis-1.3.1-5.2.5'
import Azure_CIS_131_526 from '../rules/azure-cis-1.3.1-5.2.6'

export interface azureActivityLogAlertAllOfCondition {
  allOf: [azureActivityLogAlertLeafCondition]
}

export interface azureActivityLogAlertLeafCondition {
  id: string
  field: string
  equals: string
}

export interface QueryazureActivityLogAlert {
  id: string
  region?: string
  enabled?: boolean
  condition?: azureActivityLogAlertAllOfCondition
}
export interface QueryazureResourceGroup {
  id: string
  activityLogAlerts: QueryazureActivityLogAlert[]
}

export interface CIS5xQueryResponse {
  queryazureActivityLogAlert?: QueryazureActivityLogAlert[]
  queryazureResourceGroup?: QueryazureResourceGroup[]
}

describe('CIS Microsoft Azure Foundations: 1.3.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'azure', entityName: 'CIS'} )
  })

  describe('Azure CIS 5.2.1 Ensure that Activity Log Alert exists for Create Policy Assignment', () => {
    const getTestRuleFixture = (
      region: string,
      enabled: boolean,
      field: string,
      equals: string,
    ): CIS5xQueryResponse => {
      return {
        queryazureResourceGroup: [
          {
            id: cuid(),
            activityLogAlerts: [{
              id: cuid(),
              region,
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
      data: CIS5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_521 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Create Policy Assignment', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture('global', true, 'operationName', 'microsoft.authorization/policyassignments/write')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Activity Log Alert doesnt exist for Create Policy Assignment', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture('global', true, '', '')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 5.2.2 Ensure that Activity Log Alert exists for Delete Policy Assignment', () => {
    const getTestRuleFixture = (
      region: string,
      enabled: boolean,
      field: string,
      equals: string,
    ): CIS5xQueryResponse => {
      return {
        queryazureResourceGroup: [
          {
            id: cuid(),
            activityLogAlerts: [{
              id: cuid(),
              region,
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
      data: CIS5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_522 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Delete Policy Assignment', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture('global', true, 'operationName', 'microsoft.authorization/policyassignments/delete')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Activity Log Alert doesnt exist for Delete Policy Assignment', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture('global', true, '', '')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 5.2.3 Ensure that Activity Log Alert exists for Create or Update Network Security Group', () => {
    const getTestRuleFixture = (
      region: string,
      enabled: boolean,
      field: string,
      equals: string,
    ): CIS5xQueryResponse => {
      return {
        queryazureResourceGroup: [
          {
            id: cuid(),
            activityLogAlerts: [{
              id: cuid(),
              region,
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
      data: CIS5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_523 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Create or Update Network Security Group', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture('global', true, 'operationName', 'microsoft.network/networksecuritygroups/write')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Activity Log Alert doesnt exist for Create or Update Network Security Group', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture('global', true, '', '')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 5.2.4 Ensure that Activity Log Alert exists for Delete Network Security Group', () => {
    const getTestRuleFixture = (
      region: string,
      enabled: boolean,
      field: string,
      equals: string,
    ): CIS5xQueryResponse => {
      return {
        queryazureResourceGroup: [
          {
            id: cuid(),
            activityLogAlerts: [{
              id: cuid(),
              region,
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
      data: CIS5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_524 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Delete Network Security Group', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture('global', true, 'operationName', 'microsoft.network/networksecuritygroups/delete')

      await testRule(data, Result.PASS)
    })

    test('Security Issue when Activity Log Alert doesnt exist for Delete Network Security Group', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture('global', true, '', '')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 5.2.5 Ensure that Activity Log Alert exists for Create or Update Network Security Group Rule', () => {
    const getTestRuleFixture = (
      region: string,
      enabled: boolean,
      field: string,
      equals: string,
    ): CIS5xQueryResponse => {
      return {
        queryazureResourceGroup: [
          {
            id: cuid(),
            activityLogAlerts: [{
              id: cuid(),
              region,
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
      data: CIS5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_525 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for Create or Update Network Security Group Rule', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture('global', true, 'operationName', 'microsoft.network/networksecuritygroups/securityrules/write')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Activity Log Alert doesnt exist for Create or Update Network Security Group Rule', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture('global', true, '', '')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 5.2.6 Ensure that Activity Log Alert exists for the Delete Network Security Group Rule', () => {
    const getTestRuleFixture = (
      region: string,
      enabled: boolean,
      field: string,
      equals: string,
    ): CIS5xQueryResponse => {
      return {
        queryazureResourceGroup: [
          {
            id: cuid(),
            activityLogAlerts: [{
              id: cuid(),
              region,
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
      data: CIS5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_526 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Activity Log Alert exists for the Delete Network Security Group Rule', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture('global', true, 'operationName', 'microsoft.network/networksecuritygroups/securityrules/delete')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Activity Log Alert doesnt exist for the Delete Network Security Group Rule', async () => {
      const data: CIS5xQueryResponse = getTestRuleFixture('global', true, '', '')

      await testRule(data, Result.FAIL)
    })
  })
})