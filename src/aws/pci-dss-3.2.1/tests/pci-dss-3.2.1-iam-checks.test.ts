import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_IAM_1 from '../rules/pci-dss-3.2.1-iam-check-1'
import Aws_PCI_DSS_321_IAM_2 from '../rules/pci-dss-3.2.1-iam-check-2'

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
})
