import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_cloudfront_1 from '../rules/pci-dss-3.2.1-cloudfront-check-1'
import { initRuleEngine } from '../../../utils/test'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'PCI')
  })
  describe('Cloudfront Check 1: Cloudfront distributions should be protected by WAFs', () => {
    test('Should fail when the Cloudfront distribution has no webAclId', async () => {
      const data = {
        queryawsCloudfront: [
          {
            id: cuid(),
            webAclId: ''
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_cloudfront_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when the Cloudfront distribution has a webAclId', async () => {
      const data = {
        queryawsCloudfront: [
          {
            id: cuid(),
            webAclId: cuid()
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_cloudfront_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })
})
