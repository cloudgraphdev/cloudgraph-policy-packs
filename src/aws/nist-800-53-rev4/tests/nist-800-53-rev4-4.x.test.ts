import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Aws_NIST_800_53_41 from '../rules/aws-nist-800-53-rev4-4.1'
import Aws_NIST_800_53_42 from '../rules/aws-nist-800-53-rev4-4.2'
import Aws_NIST_800_53_43 from '../rules/aws-nist-800-53-rev4-4.3'
import Aws_NIST_800_53_44 from '../rules/aws-nist-800-53-rev4-4.4'
import Aws_NIST_800_53_45 from '../rules/aws-nist-800-53-rev4-4.5'
import Aws_NIST_800_53_46 from '../rules/aws-nist-800-53-rev4-4.6'

export interface DefaultCacheBehavior {
  viewerProtocolPolicy?: string | null
}

export interface CustomOriginConfig {
  originProtocolPolicy?: string | null
}

export interface Origin {
  domainName?: string | null
  customOriginConfig: CustomOriginConfig
}

export interface Listener {
  loadBalancerProtocol: string
}

export interface Condition {
  key: string
  value: string[]
}

export interface Principal {
  key: string
  value: string[]
}

export interface Statement {
  effect: string
  action: string[]
  principal: Principal[]
  condition: Condition[]
}

export interface Policy {
  statement: Statement[]
}

export interface Subscription {
  protocol: string
  endpoint: string
}

export interface QueryawsS3 {
  id: string
  policy: Policy
}

export interface QueryawsCloudfront {
  id: string
  origins?: Origin[]
  defaultCacheBehavior?: DefaultCacheBehavior
}

export interface QueryawsElastiCacheCluster {
  id: string
  transitEncryptionEnabled: boolean
}

export interface QueryawsElb {
  id: string
  listeners: Listener[]
}

export interface QueryawsSns {
  id: string
  subscriptions: Subscription[]
}

export interface NIS4xQueryResponse {
  queryawsCloudfront?: QueryawsCloudfront[]
  queryawsElastiCacheCluster?: QueryawsElastiCacheCluster[]
  queryawsElb?: QueryawsElb[]
  queryawsS3?: QueryawsS3[]
  queryawsSns?: QueryawsSns[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'NIST')
  })

  describe('AWS NIST 4.1 CloudFront distribution origin should be set to S3 or origin protocol policy should be set to https-only', () => {
    const getTestRuleFixture = (
      domainName: string | null,
      originProtocolPolicy: string | null
    ): NIS4xQueryResponse => {
      return {
        queryawsCloudfront: [
          {
            id: cuid(),
            origins: [
              {
                domainName,
                customOriginConfig: {
                  originProtocolPolicy,
                },
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_41 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when CloudFront distribution origin is set to S3', async () => {
      const data: NIS4xQueryResponse = getTestRuleFixture(
        'test-cloudfront.s3.us-east-1.amazonaws.com',
        null
      )
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when CloudFront distribution origin protocol policy is set to https-only', async () => {
      const data: NIS4xQueryResponse = getTestRuleFixture(null, 'https-only')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when CloudFront distribution origin is not set to S3 and origin protocol policy is not set to https-only', async () => {
      const data: NIS4xQueryResponse = getTestRuleFixture(
        'test-cloudfront.elb.us-east-1.amazonaws.com',
        'http-only'
      )
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 4.2 CloudFront viewer protocol policy should be set to https-only or redirect-to-https', () => {
    const getTestRuleFixture = (
      viewerProtocolPolicy: string | null
    ): NIS4xQueryResponse => {
      return {
        queryawsCloudfront: [
          {
            id: cuid(),
            defaultCacheBehavior: {
              viewerProtocolPolicy,
            },
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_42 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when CloudFront viewer protocol policy should is set to https-only', async () => {
      const data: NIS4xQueryResponse = getTestRuleFixture('https-only')
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when CloudFront viewer protocol policy should is set to redirect-to-https', async () => {
      const data: NIS4xQueryResponse = getTestRuleFixture('redirect-to-https')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when CloudFront viewer protocol policy should is set to https-only', async () => {
      const data: NIS4xQueryResponse = getTestRuleFixture('http-only')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 4.3 ElastiCache transport encryption should be enabled', () => {
    const getTestRuleFixture = (
      transitEncryptionEnabled: boolean
    ): NIS4xQueryResponse => {
      return {
        queryawsElastiCacheCluster: [
          {
            id: cuid(),
            transitEncryptionEnabled,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_43 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ElastiCache transport encryption is enabled', async () => {
      const data: NIS4xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when ElastiCache transport encryption is not enabled', async () => {
      const data: NIS4xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 4.4 ELBv1 listener protocol should not be set to http', () => {
    const getTestRuleFixture = (
      loadBalancerProtocol: string
    ): NIS4xQueryResponse => {
      return {
        queryawsElb: [
          {
            id: cuid(),
            listeners: [
              {
                loadBalancerProtocol,
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_44 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ELBv1 listener protocol should is set to https', async () => {
      const data: NIS4xQueryResponse = getTestRuleFixture('HTTPS')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when ELBv1 listener protocol should is set to http', async () => {
      const data: NIS4xQueryResponse = getTestRuleFixture('HTTP')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 4.5 S3 bucket policies should only allow requests that use HTTPS', () => {
    const getTestRuleFixture = (
      effect: string,
      action: string,
      principal: Principal,
      condition: Condition
    ): NIS4xQueryResponse => {
      return {
        queryawsS3: [
          {
            id: cuid(),
            policy: {
              statement: [
                {
                  effect,
                  action: [action],
                  principal: [principal],
                  condition: [condition],
                },
              ],
            },
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_45 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when S3 bucket policies only allow requests that use HTTPS', async () => {
      const principal: Principal = {
        key: 'AWS',
        value: ['*'],
      }
      const condition: Condition = {
        key: 'aws:SecureTransport',
        value: ['false'],
      }
      const data: NIS4xQueryResponse = getTestRuleFixture(
        'Deny',
        '*',
        principal,
        condition
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when S3 bucket policy does not have SecureTransport enabled', async () => {
      const principal: Principal = {
        key: 'AWS',
        value: ['arn:aws:iam::111122223333:root'],
      }
      const condition: Condition = {
        key: 'aws:SecureTransport',
        value: ['false'],
      }
      const data: NIS4xQueryResponse = getTestRuleFixture(
        'Allow',
        '*',
        principal,
        condition
      )

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when S3 bucket policy have SecureTransport enabled but grants permission to any public anonymous users', async () => {
      const principal: Principal = { key: '', value: ['*'] }
      const condition: Condition = {
        key: 'aws:SecureTransport',
        value: ['true'],
      }
      const data: NIS4xQueryResponse = getTestRuleFixture(
        'Allow',
        '*',
        principal,
        condition
      )

      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 4.6 SNS subscriptions should deny access via HTTP', () => {
    const getTestRuleFixture = (
      protocol: string,
      endpoint: string
    ): NIS4xQueryResponse => {
      return {
        queryawsSns: [
          {
            id: cuid(),
            subscriptions: [
              {
                protocol,
                endpoint,
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_46 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when SNS subscriptions deny access via HTTP', async () => {
      const data: NIS4xQueryResponse = getTestRuleFixture(
        'https',
        'https://06c5056f74ab.ngrok.io/sns-response-endpoint'
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when SNS subscriptions allow access via HTTP protocol', async () => {
      const data: NIS4xQueryResponse = getTestRuleFixture(
        'http',
        'https://06c5056f74ab.ngrok.io/sns-response-endpoint'
      )

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when SNS subscriptions allow access via HTTP domain', async () => {
      const data: NIS4xQueryResponse = getTestRuleFixture(
        'https',
        'http://06c5056f74ab.ngrok.io/sns-response-endpoint'
      )

      await testRule(data, Result.FAIL)
    })
  })
})
