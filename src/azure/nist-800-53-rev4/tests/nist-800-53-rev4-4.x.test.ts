import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Azure_NIST_800_53_41 from '../rules/azure-nist-800-53-rev4-4.1'
import Azure_NIST_800_53_42 from '../rules/azure-nist-800-53-rev4-4.2'
import Azure_NIST_800_53_43 from '../rules/azure-nist-800-53-rev4-4.3'

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

export interface NIST4XQueryResponse {
  queryazurePolicyAssignment?: QueryazurePolicyAssignment[]
}

describe('Azure NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'azure',
      entityName: 'NIST',
    })
  })

  describe('Azure NIST 4.1 Security Center default policy setting ‘Monitor Network Security Groups’ should be enabled', () => {
    const getTestRuleFixture = (
      displayName: string,
      parameters: Parameter[]
    ): NIST4XQueryResponse => {
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
      data: NIST4XQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_41 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ‘Monitor Network Security Groups’ is enabled', async () => {
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

      const data: NIST4XQueryResponse = getTestRuleFixture(
        'Network Security Groups on the subnet level should be enabled',
        parameters
      )

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when definition is not ‘Monitor Network Security Groups’', async () => {

      const data: NIST4XQueryResponse = getTestRuleFixture(
        'This can be any other measure or text',
        []
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when  ‘Monitor Network Security Groups’ is not enabled', async () => {

      const data: NIST4XQueryResponse = getTestRuleFixture(
        'Network Security Groups on the subnet level should be enabled',
        []
      )

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when ‘Monitor Network Security Groups’ not have set the parameter ‘AuditIfNotExists’', async () => {
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

      const data: NIST4XQueryResponse = getTestRuleFixture(
        'Network Security Groups on the subnet level should be enabled',
        parameters
      )

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 4.2 Security Center default policy setting ‘Monitor OS Vulnerabilities’ should be enabled', () => {
    const getTestRuleFixture = (
      displayName: string,
      parameters: Parameter[]
    ): NIST4XQueryResponse => {
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
      data: NIST4XQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_42 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ‘Monitor OS Vulnerabilities’ is enabled', async () => {
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

      const data: NIST4XQueryResponse = getTestRuleFixture(
        'Vulnerability assessment should be enabled on virtual machines',
        parameters
      )

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when definition is not ‘Monitor OS Vulnerabilities’', async () => {

      const data: NIST4XQueryResponse = getTestRuleFixture(
        'This can be any other measure or text',
        []
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when ‘Monitor OS Vulnerabilities’ is not enabled', async () => {

      const data: NIST4XQueryResponse = getTestRuleFixture(
        'Vulnerability assessment should be enabled on virtual machines',
        []
      )

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when ‘Monitor OS Vulnerabilities’ not have set the parameter ‘AuditIfNotExists’', async () => {
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

      const data: NIST4XQueryResponse = getTestRuleFixture(
        'Vulnerability assessment should be enabled on virtual machines',
        parameters
      )

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 4.3 Security Center default policy setting ‘Monitor Vulnerability Assessment’ should be enabled', () => {
    const getTestRuleFixture = (
      displayName: string,
      parameters: Parameter[]
    ): NIST4XQueryResponse => {
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
      data: NIST4XQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_43 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ‘Monitor Vulnerability Assessment’ is enabled', async () => {
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

      const data: NIST4XQueryResponse = getTestRuleFixture(
        'Vulnerability assessment should be enabled on virtual machines',
        parameters
      )

      await testRule(data, Result.PASS)
    })

    test('No Security Issue when definition is not ‘Monitor Vulnerability Assessment’', async () => {

      const data: NIST4XQueryResponse = getTestRuleFixture(
        'This can be any other measure or text',
        []
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when ‘Monitor Vulnerability Assessment’ is not enabled', async () => {

      const data: NIST4XQueryResponse = getTestRuleFixture(
        'Vulnerability assessment should be enabled on virtual machines',
        []
      )

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when ‘Monitor Vulnerability Assessment’ not have set the parameter ‘AuditIfNotExists’', async () => {
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

      const data: NIST4XQueryResponse = getTestRuleFixture(
        'Vulnerability assessment should be enabled on virtual machines',
        parameters
      )

      await testRule(data, Result.FAIL)
    })
  })
})