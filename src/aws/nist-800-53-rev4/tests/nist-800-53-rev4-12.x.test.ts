import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_NIST_800_53_121 from '../rules/aws-nist-800-53-rev4-12.1'
import Aws_NIST_800_53_122 from '../rules/aws-nist-800-53-rev4-12.2'


export interface Logging {
  enabled: boolean
}

export interface DataResource {
  type: string
}

export interface EventSelector {
  readWriteType?: string
  includeManagementEvents?: boolean
  dataResources?: DataResource[]
}

export interface Cloudtrail {
  isMultiRegionTrail?: string
  eventSelectors?: EventSelector[]
  includeGlobalServiceEvents?: string
}

export interface QueryawsCloudfront {
  id: string
  logging: Logging
}

export interface QueryawsAccount {
  id: string
  cloudtrail: Cloudtrail[]
}

export interface QueryawsCloudtrail {
  id: string
  eventSelectors?: EventSelector[]
}

export interface QueryawsAlb {
  id: string
  accessLogsEnabled: string
}

export interface QueryawsElb {
  id: string
  accessLogs: string
}

export interface NIS6xQueryResponse {
  queryawsCloudfront?: QueryawsCloudfront[]
  queryawsAccount?: QueryawsAccount[]
  queryawsCloudtrail?: QueryawsCloudtrail[]
  queryawsAlb?: QueryawsAlb[]
  queryawsElb?: QueryawsElb[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'NIST',
    })
  })

  //12.X
  describe(' AWS 12.1 CloudFront distributions should have geo-restrictions specified', () => {
    const getTestRuleFixture = (geoRestrictions: string): any => {
      return {
        queryawsCloudfront: [
          {
            id: cuid(),
            geoRestrictions
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: any,
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

    test('Georestrictions allowed. Content is available', async () => {
      const data: any = getTestRuleFixture('Whitelist')
      await testRule(data, Result.PASS)
    })

    test('Georestrictions allowed. Content is available', async () => {
      const data: any = getTestRuleFixture('None')
      await testRule(data, Result.PASS)
    })

    test('Georestrictions allowed. Content is not available', async () => {
      const data: any = getTestRuleFixture('Blacklist')
      await testRule(data, Result.FAIL)
    })

  })

  describe(' AWS 12.2 EC2 instances should not have a public IP association (IPv4)', () => {
    const getTestRuleFixture = (autoAssignPublicIpv4Address: string): any => {
      return {
        queryawsEc2: [
          {
            id: cuid(),            
            subnet: [              
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
      data: any,
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

    test('Subnet is Default and auto assign attribute is true', async () => {
      const data: any = getTestRuleFixture('Yes')
      await testRule(data, Result.FAIL)
    })

    test('Subnet is nonDefault and auto assign attribute cannot be false', async () => {
      const data: any = getTestRuleFixture('No')
      await testRule(data, Result.PASS)
    })

  })

})
