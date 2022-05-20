import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_PCI_DSS_321_Logging_1 from '../rules/pci-dss-3.2.1-logging-check-1'

export interface LogSink {
  filter?: string
  destination?: string
}

export interface QuerygcpProject {
  id: string
  logSinks: LogSink[]
}

export interface PCIQueryResponse {
  querygcpProject?: QuerygcpProject[]
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'PCI'} )
  })

  describe('Logging check 1: At least one project-level logging sink should be configured with an empty filter', () => {
    const getTestRuleFixture = (filter: string): PCIQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            logSinks: [
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
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_Logging_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is a logSink with an empty filter', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('')
      await test22Rule(data, Result.PASS)
    })

    test('Security Issue when there is a logSink with an empty filter', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('dummy-filter')
      await test22Rule(data, Result.FAIL)
    })
  })

})
