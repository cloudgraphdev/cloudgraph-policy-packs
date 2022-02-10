import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_Autoscaling_1 from '../rules/pci-dss-3.2.1-autoscaling-check-1'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine('aws', 'PCI')
  })
  describe('Autoscaling Check 1: Auto Scaling groups associated with a load balancer should use health checks', () => {
    test('Should fail when it contains an invalid health check type and zero load balancers', async () => {
      const data = {
        queryawsAsg: [
          {
            id: cuid(),
            loadBalancerNames: [],
            healthCheckType: 'EC2',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Autoscaling_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when it contains a valid health check type and zero load balancers', async () => {
      const data = {
        queryawsAsg: [
          {
            id: cuid(),
            loadBalancerNames: [],
            healthCheckType: 'ELB',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Autoscaling_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when it contains a valid health check type and at least one load balancer', async () => {
      const data = {
        queryawsAsg: [
          {
            id: cuid(),
            loadBalancerNames: ['alb_1', 'alb2'],
            healthCheckType: 'ELB',
          },
        ],
      }


      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Autoscaling_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })
})
