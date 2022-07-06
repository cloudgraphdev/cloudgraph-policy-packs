import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_Dms_1 from '../rules/pci-dss-3.2.1-dms-check-1'
import { initRuleEngine } from '../../../utils/test'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'PCI')
  })

  describe('DMS Check 1: AWS Database Migration Service replication instances should not be public', () => {
    test('Should pass when it is not publically accessible', async () => {
      const data = {
        queryawsDmsReplicationInstance: [
          {
            id: cuid(),
            publiclyAccessible: false
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Dms_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when it is publically accessible', async () => {
      const data = {
        queryawsDmsReplicationInstance: [
          {
            id: cuid(),
            publiclyAccessible: true
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Dms_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })
})
