import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_Elbv2_1 from '../rules/pci-dss-3.2.1-elbv2-check-1'
import { initRuleEngine } from '../../../utils/test'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'PCI')
  })

  describe('ELBV2 Check 1: Application Load Balancer should be configured to redirect all HTTP requests to HTTPS', () => {
    test('Should pass when it does not have a HTTP listener configured', async () => {
      const data = {
        queryawsAlb: [
          {
            id: cuid(),
            listeners: [
              {
                settings: {
                  protocol: `HTTPS:443 ${cuid()}`,
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
        Aws_PCI_DSS_321_Elbv2_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when it does not have a redirect configured for a HTTP listener', async () => {
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
              {
                settings: {
                  protocol: `HTTPS:443 ${cuid()}`,
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
        Aws_PCI_DSS_321_Elbv2_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when it does not have any listeners configured', async () => {
      const data = {
        queryawsAlb: [
          {
            id: cuid(),
            listeners: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Elbv2_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass when it has at least one redirect configured for a HTTP listener', async () => {
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
        Aws_PCI_DSS_321_Elbv2_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })
})
