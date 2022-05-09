import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_NIST_800_53_161 from '../rules/aws-nist-800-53-rev4-16.1'
import Aws_NIST_800_53_162 from '../rules/aws-nist-800-53-rev4-16.2'
import Aws_NIST_800_53_163 from '../rules/aws-nist-800-53-rev4-16.3'
import Aws_NIST_800_53_164 from '../rules/aws-nist-800-53-rev4-16.4'
import Aws_NIST_800_53_165 from '../rules/aws-nist-800-53-rev4-16.5'
import Aws_NIST_800_53_166 from '../rules/aws-nist-800-53-rev4-16.6'

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

  //16.1
  describe.skip('API Gateway classic custom domains should use secure TLS protocol versions (1.2 and above)', () => {
    const getTestRuleFixture = (principalRole: string): any => {
      return {
        queryawsIamRole: [
          {
            id: cuid(),
            assumeRolePolicy: {
              statement: [
                {
                  principal: [
                    {
                      value: [principalRole],
                    },
                  ],
                },
              ],
            },
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
        Aws_NIST_800_53_161 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when IAM role trust policies not allow all principals to assume the role', async () => {
      const data: any = getTestRuleFixture(
        'arn:aws:iam::204762158545:root'
      )
      await testRule(data, Result.PASS)
    })
  })

  //16.2
  describe.skip('API Gateway v2 custom domains should use secure TLS protocol versions (1.2 and above) ', () => { 
    const getTestRuleFixture = ( effect: string): any => {
      return {
        queryawsIamRole: [
          {
           
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
        Aws_NIST_800_53_162 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('', async () => {
      const data: any = getTestRuleFixture('data')
      await testRule(data, Result.PASS)
    })

  })

   //16.3
   describe.skip('CloudFront distribution custom origins should use secure TLS protocol versions (1.2 and above) ', () => { 
    const getTestRuleFixture = ( minimumProtocolVersion: string): any => {
      return {
        queryawsCloudfront: [
          {
            id: cuid(),
            viewerCertificate: 
              {
                minimumProtocolVersion,
              },            
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
        Aws_NIST_800_53_163 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('Customs origins is secured, version up to date', async () => {
      const data: any = getTestRuleFixture('TLSv1.2')
      await testRule(data, Result.PASS)
    })

    test('Customs origins is secured, version up to date', async () => {
      const data: any = getTestRuleFixture('TLSv1.3')
      await testRule(data, Result.PASS)
    })

    test('Customs origins is not secured, version not up to date', async () => {
      const data: any = getTestRuleFixture('TLSv1')
      await testRule(data, Result.FAIL)
    })

  })

  //16.4
  describe('CloudFront distribution viewer certificate should use secure TLS protocol versions (1.2 and above) ', () => { 
    const getTestRuleFixture = ( items: string[]): any => {
      return {
        queryawsCloudfront: [
          {
            id: cuid(),
            origins: 
              {
                customOriginConfig: 
                  {
                    originSslProtocols: 
                      {
                        items,
                      }                     
                  }                 
              }            
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
        Aws_NIST_800_53_164 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('distribution viewer certificate is secured, version up to date', async () => {
      const data: any = getTestRuleFixture(['TLSv1.2'])
      await testRule(data, Result.PASS)
    })

    test('distribution viewer certificate is secured, version up to date', async () => {
      const data: any = getTestRuleFixture(['TLSv1.3'])
      await testRule(data, Result.PASS)
    })

    test('distribution viewer certificate is secured, version up to date', async () => {
      const data: any = getTestRuleFixture(['TLSv1.2', 'TLSv1.3'])
      await testRule(data, Result.PASS)
    })

    test('distribution viewer certificate is not secured, version not up to date', async () => {
      const data: any = getTestRuleFixture(['TLSv1'])
      await testRule(data, Result.FAIL)
    })

    test('distribution viewer certificate is not secured, version not up to date', async () => {
      const data: any = getTestRuleFixture(['TLSv1', 'TLSv1.2'])
      await testRule(data, Result.FAIL)
    })

  })

})
