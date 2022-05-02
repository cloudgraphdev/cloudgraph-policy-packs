import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_Lambda_1 from '../rules/pci-dss-3.2.1-lambda-check-1'
import Aws_PCI_DSS_321_Lambda_2 from '../rules/pci-dss-3.2.1-lambda-check-2'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'PCI',
    })
  })

  describe('Lambda Check 1: Lambda functions should prohibit public access', () => {
    test('Should pass when the policy does not exist', async () => {
      const data = {
        queryawsLambda: [
          {
            id: cuid(),
            policy: null
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Lambda_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass when the policy does not allow public access', async () => {
      const data = {
        queryawsLambda: [
          {
            id: cuid(),
            policy: {
              statement: [
                {
                  effect: 'Allow',
                  principal: [
                    {
                      key: 'Service',
                      value: ['lambda.amazonaws.com'],
                    },
                  ],
                },
              ],
            }
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Lambda_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when the policy has a * principal', async () => {
      const data = {
        queryawsLambda: [
          {
            id: cuid(),
            policy: {
              statement: [
                {
                  effect: 'Allow',
                  principal: [
                    {
                      key: '',
                      value: ['*'],
                    },
                  ],
                },
              ],
            }
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Lambda_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when the policy has a {AWS: `*`} principal', async () => {
      const data = {
        queryawsLambda: [
          {
            id: cuid(),
            policy: {
              statement: [
                {
                  effect: 'Allow',
                  principal: [
                    {
                      key: 'AWS',
                      value: ['*'],
                    },
                  ],
                },
              ],
            }
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Lambda_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when the policy has a DENY {AWS: `*`} principal', async () => {
      const data = {
        queryawsLambda: [
          {
            id: cuid(),
            policy: {
              statement: [
                {
                  effect: 'Deny',
                  principal: [
                    {
                      key: 'AWS',
                      value: ['*'],
                    },
                  ],
                },
              ],
            }
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Lambda_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })
  describe('Lambda Check 2: Lambda functions should be in a VPC', () => {
    test('Should pass when it does have a vpcId', async () => {
      const data = {
        queryawsLambda: [
          {
            id: cuid(),
            vpcConfig: {
              vpcId: cuid()
            }
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Lambda_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when it does not have a vpcConfig obj', async () => {
      const data = {
        queryawsLambda: [
          {
            id: cuid(),
            vpcConfig: null
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Lambda_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when it has an empty vpcConfig', async () => {
      const data = {
        queryawsLambda: [
          {
            id: cuid(),
            vpcConfig: {}
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Lambda_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when it has an empty string as vpcId', async () => {
      const data = {
        queryawsLambda: [
          {
            id: cuid(),
            vpcConfig: {
              vpcId: ''
            }
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Lambda_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })
})
