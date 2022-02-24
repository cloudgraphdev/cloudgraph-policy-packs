import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_Alb_1 from '../rules/pci-dss-3.2.1-alb-check-1'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'PCI',
    })
  })

  describe('ELBV2 Check 1: Application Load Balancer should be configured to redirect all HTTP requests to HTTPS', () => {
    test('Should fail when it does not have a redirect listener configured', async () => {
      const data = {
        queryawsAlb: [
          {
            id: cuid(),
            listeners: [
              {
                settings: {
                  protocol: `HTTP:80 ${cuid()}`,
                  rules: [
                    {
                      type: 'forward',
                      redirectProtocol: null,
                    },
                  ],
                },
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Alb_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when it does not have any redirect listener configured', async () => {
      const data = {
        queryawsAlb: [
          {
            id: cuid(),
            listeners: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Alb_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when it has at least one redirect listener configured', async () => {
      const data = {
        queryawsAlb: [
          {
            id: cuid(),
            listeners: [
              {
                settings: {
                  protocol: `HTTP:80 ${cuid()}`,
                  rules: [
                    {
                      type: 'forward',
                      redirectProtocol: null,
                    },
                    {
                      type: 'redirect',
                      redirectProtocol: 'HTTPS',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Alb_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })
})
