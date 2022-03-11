import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_Rds_2 from '../rules/pci-dss-3.2.1-rds-check-2'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'PCI',
    })
  })
  describe('RDS Check 2: RDS DB Instances should prohibit public access', () => {
    test('Should fail when publiclyAccessible is true', async () => {
      const data = {
        queryawsRdsDbInstance: [
          {
            id: cuid(),
            publiclyAccessible: true
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Rds_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when publiclyAccessible is false', async () => {
      const data = {
        queryawsRdsDbInstance: [
          {
            id: cuid(),
            publiclyAccessible: false
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Rds_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })
})
