import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_EC2_6 from '../rules/pci-dss-3.2.1-ec2-check-6'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'PCI',
    })
  })

  describe('EC2 Check 6: VPC flow logging should be enabled in all VPCs', () => {
    test('Should pass when flow logging is enabled for each VPC', async () => {
      const data = {
        queryawsVpc: [
          {
            id: cuid(),
            flowLogs: [
              {
                resourceId: cuid(),
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_EC2_6 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when flow logging is disabled on one VPC', async () => {
      const data = {
        queryawsVpc: [
          {
            id: cuid(),
            flowLogs: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_EC2_6 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })
})
