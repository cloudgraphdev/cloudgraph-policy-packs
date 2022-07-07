import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Aws_NIST_800_53_141 from '../rules/aws-nist-800-53-rev4-14.1'

export interface QueryawsCloudfront {
  id: string
  webAclId: string
}

export interface NIS14xQueryResponse {
  queryawsCloudfront?: QueryawsCloudfront[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'NIST')
  })

  describe('AWS NIST 14.1 CloudFront distributions should be protected by WAFs', () => {
    const getTestRuleFixture = (webAclId: string): NIS14xQueryResponse => {
      return {
        queryawsCloudfront: [
          {
            id: cuid(),
            webAclId
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS14xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_141 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when the Cloudfront distribution has a webAclId', async () => {
      const data: NIS14xQueryResponse = getTestRuleFixture(cuid())
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the Cloudfront distribution has no webAclId', async () => {
      const data: NIS14xQueryResponse = getTestRuleFixture('')
      await testRule(data, Result.FAIL)
    })
  })
})
