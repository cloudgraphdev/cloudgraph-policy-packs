import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_Redshift_1 from '../rules/pci-dss-3.2.1-redshift-check-1'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'PCI',
    })
  })
  describe('Redshift Check 1: Amazon Redshift clusters should prohibit public access', () => {
    test('Should fail when publiclyAccessible is true', async () => {
      const data = {
        queryawsRedshiftCluster: [
          {
            id: cuid(),
            publiclyAccessible: true
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Redshift_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when publiclyAccessible is false', async () => {
      const data = {
        queryawsRedshiftCluster: [
          {
            id: cuid(),
            publiclyAccessible: false
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Redshift_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })
})
