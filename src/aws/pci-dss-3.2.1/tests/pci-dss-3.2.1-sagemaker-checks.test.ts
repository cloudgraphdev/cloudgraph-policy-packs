import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_SageMaker_1 from '../rules/pci-dss-3.2.1-sagemaker-check-1'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'PCI',
    })
  })
  describe('sagemaker Check 1: Amazon SageMaker notebook instances should not have direct internet access', () => {
    test('Should fail when directInternetAccess is true', async () => {
      const data = {
        queryawsSageMakerNotebookInstance: [
          {
            id: cuid(),
            directInternetAccess: true
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_SageMaker_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when directInternetAccess is false', async () => {
      const data = {
        queryawsSageMakerNotebookInstance: [
          {
            id: cuid(),
            directInternetAccess: false
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_SageMaker_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })
})
