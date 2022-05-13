import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_NIST_800_53_121 from '../rules/aws-nist-800-53-rev4-12.1'
import Aws_NIST_800_53_122 from '../rules/aws-nist-800-53-rev4-12.2'

export interface GeoRestriction {
  restrictionType: string
  locations: string[]
}

export interface Subnet {
  autoAssignPublicIpv4Address: string
}
export interface QueryawsEc2 {
  id: string
  subnets: Subnet[]
}

export interface QueryawsCloudfront {
  id: string
  geoRestriction: GeoRestriction
}

export interface NIST12xQueryResponse {
  queryawsCloudfront?: QueryawsCloudfront[]
  queryawsEc2?: QueryawsEc2[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'NIST',
    })
  })

  describe('AWS NIST 12.1 CloudFront distributions should have geo-restrictions specified', () => {
    const getTestRuleFixture = (
      restrictionType: string,
      locations: string[]
      ): NIST12xQueryResponse => {
      return {
        queryawsCloudfront: [
          {
            id: cuid(),
            geoRestriction: {
              restrictionType,
              locations
            },
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST12xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_121 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a restrictionType equal to whitelist and locations specified', async () => {
      const data: NIST12xQueryResponse = getTestRuleFixture('whitelist', ['CA','US'])
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a restrictionType equal to whitelist and locations specified', async () => {
      const data: NIST12xQueryResponse = getTestRuleFixture('blacklist', ['CA','US'])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule without geoRestriction specified', async () => {
      const data: NIST12xQueryResponse = getTestRuleFixture('none', [])
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 12.2 EC2 instances should not have a public IP association (IPv4)', () => {
    const getTestRuleFixture = (autoAssignPublicIpv4Address: string): NIST12xQueryResponse => {
      return {
        queryawsEc2: [
          {
            id: cuid(),            
            subnets: [              
              {
                autoAssignPublicIpv4Address,
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST12xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_122 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when EC2 instances not have a public IP association (IPv4)', async () => {
      const data: NIST12xQueryResponse = getTestRuleFixture('No')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when EC2 instances have a public IP association (IPv4)', async () => {
      const data: NIST12xQueryResponse = getTestRuleFixture('Yes')
      await testRule(data, Result.FAIL)
    })
  })
})
