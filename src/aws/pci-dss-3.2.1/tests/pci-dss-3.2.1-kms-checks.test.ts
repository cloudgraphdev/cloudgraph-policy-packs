import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_Kms_1 from '../rules/pci-dss-3.2.1-kms-check-1'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'PCI',
    })
  })

  describe('KMS Check 1: KMS key rotation should be enabled', () => {
    test('Should pass when the key is managed by CUSTOMER and has rotation enabled', async () => {
      const data = {
        queryawsKms: [
          {
            id: cuid(),
            keyManager: 'CUSTOMER',
            keyRotationEnabled: true
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Kms_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass when the key is managed by AWS', async () => {
      const data = {
        queryawsKms: [
          {
            id: cuid(),
            keyManager: 'AWS',
            keyRotationEnabled: false
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Kms_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when the key is managed by CUSTOMER and doesnt have rotation enabled', async () => {
      const data = {
        queryawsKms: [
          {
            id: cuid(),
            keyManager: 'CUSTOMER',
            keyRotationEnabled: false
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Kms_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })
})
