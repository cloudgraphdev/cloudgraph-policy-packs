import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_IAM_1 from '../rules/pci-dss-3.2.1-iam-check-1'
import Aws_PCI_DSS_321_IAM_2 from '../rules/pci-dss-3.2.1-iam-check-2'
import Aws_PCI_DSS_321_IAM_3 from '../rules/pci-dss-3.2.1-iam-check-3'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'PCI',
    })
  })

  describe('IAM Check 1: IAM root user access key should not exist', () => {
    test('Should fail when it finds a user called root', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when it does not find a user called root', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'user',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('IAM Check 2: IAM root user access key should not exist', () => {
    test('Should fail when a user has attached policies directly', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            iamAttachedPolicies: [{ id: cuid() }],
            inlinePolicies: ['inline_test'],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when a user does not have attached policies directly', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            iamAttachedPolicies: [],
            inlinePolicies: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('IAM Check 3: IAM policies should not allow full "*" administrative privileges', () => {
    test('Should pass for IAM policies that not allow full "*:*" administrative privileges', async () => {
      const data = {
        queryawsIamPolicy: [
          {
            id: cuid(),
            policyContent: {
              statement: [
                {
                  effect: 'Allow',
                  action: [
                    'secretsmanager:DeleteSecret',
                    'secretsmanager:GetSecretValue',
                    'secretsmanager:UpdateSecret',
                  ],
                  resource: ['arn:aws:secretsmanager:*:*:secret:A4B*'],
                },
              ],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_3 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass for IAM policies that have a statement with "Effect": "Allow" with "Action": "*" over restricted "Resource"', async () => {
      const data = {
        queryawsIamPolicy: [
          {
            id: cuid(),
            policyContent: {
              statement: [
                {
                  effect: 'Allow',
                  action: ['*'],
                  resource: ['arn:aws:secretsmanager:*:*:secret:A4B*'],
                },
              ],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_3 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass for IAM policies that have a statement with "Effect": "Allow" with restricted "Action" over "Resource": "*"', async () => {
      const data = {
        queryawsIamPolicy: [
          {
            id: cuid(),
            policyContent: {
              statement: [
                {
                  effect: 'Allow',
                  action: [
                    'secretsmanager:DeleteSecret',
                    'secretsmanager:GetSecretValue',
                    'secretsmanager:UpdateSecret',
                  ],
                  resource: ['*'],
                },
              ],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_3 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail for IAM policies that allow full "*:*" administrative privileges', async () => {
      const data = {
        queryawsIamPolicy: [
          {
            id: cuid(),
            policyContent: {
              statement: [
                {
                  effect: 'Allow',
                  action: ['*'],
                  resource: ['*'],
                },
              ],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_3 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })
})
