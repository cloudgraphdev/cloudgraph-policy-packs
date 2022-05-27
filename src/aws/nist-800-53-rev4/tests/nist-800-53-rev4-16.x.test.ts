import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_NIST_800_53_161 from '../rules/aws-nist-800-53-rev4-16.1'
import Aws_NIST_800_53_162 from '../rules/aws-nist-800-53-rev4-16.2'
import Aws_NIST_800_53_163 from '../rules/aws-nist-800-53-rev4-16.3'
import Aws_NIST_800_53_164 from '../rules/aws-nist-800-53-rev4-16.4'
import Aws_NIST_800_53_165 from '../rules/aws-nist-800-53-rev4-16.5'
import Aws_NIST_800_53_166 from '../rules/aws-nist-800-53-rev4-16.6'

export interface ViewerCertificate {
  minimumProtocolVersion: string
}

export interface OriginSslProtocols {
  items: string[]
}

export interface CustomOriginConfig {
  originSslProtocols: OriginSslProtocols
}
export interface Origin {
  customOriginConfig: CustomOriginConfig
}

export interface QueryawsCloudfront {
  id: string
  origins?: Origin[]
  viewerCertificate?: ViewerCertificate
}

export interface Configuration {
  securityPolicy: string
}

export interface DomainName {
  configurations: Configuration[]
}

export interface QueryawsApiGatewayRestApi {
  id: string
  domainNames: DomainName[]
}

export interface QueryawsApiGatewayHttpApi {
  id: string
  domainNames: DomainName[]
}

export interface Settings {
  protocol: string
  sslPolicy: string
}
export interface Listener {
  settings?: Settings
  loadBalancerProtocol?: string
  sslCertificateId?: string | null
}

export interface QueryawsAlb {
  id: string
  listeners: Listener[]
}

export interface QueryawsElb {
  id: string
  listeners: Listener[]
}
export interface NIST16xQueryResponse {
  queryawsCloudfront?: QueryawsCloudfront[]
  queryawsApiGatewayRestApi?: QueryawsApiGatewayRestApi[]
  queryawsApiGatewayHttpApi?: QueryawsApiGatewayHttpApi[]
  queryawsElb?: QueryawsElb[]
  queryawsAlb?: QueryawsAlb[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'NIST',
    })
  })

  describe('AWS NIST 16.1 API Gateway classic custom domains should use secure TLS protocol versions (1.2 and above)', () => {
    const getTestRuleFixture = (
      securityPolicy: string
    ): NIST16xQueryResponse => {
      return {
        queryawsApiGatewayRestApi: [
          {
            id: cuid(),
            domainNames: [
              {
                configurations: [
                  {
                    securityPolicy,
                  },
                ],
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST16xQueryResponse,
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

    test('No Security Issue when API Gateway classic custom domains use secure TLS protocol versions 1.2 and above', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture('TLS_1_2')
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when API Gateway classic custom domains is not set', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture('')
      const restApi = data
        .queryawsApiGatewayRestApi?.[0] as QueryawsApiGatewayRestApi
      restApi.domainNames = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when API Gateway classic custom domains use secure TLS protocol versions older than 1.2', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture('TLS_1_0')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 16.2 API Gateway v2 custom domains should use secure TLS protocol versions (1.2 and above)', () => {
    const getTestRuleFixture = (
      securityPolicy: string
    ): NIST16xQueryResponse => {
      return {
        queryawsApiGatewayHttpApi: [
          {
            id: cuid(),
            domainNames: [
              {
                configurations: [
                  {
                    securityPolicy,
                  },
                ],
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST16xQueryResponse,
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

    test('No Security Issue when API Gateway v2 custom domains use secure TLS protocol versions 1.2 and above', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture('TLS_1_2')
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when API Gateway v2 custom domains is not set', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture('')
      const httpApi = data
        .queryawsApiGatewayHttpApi?.[0] as QueryawsApiGatewayHttpApi
      httpApi.domainNames = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when API Gateway v2 custom domains use secure TLS protocol versions older than 1.2', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture('TLS_1_0')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 16.3 CloudFront distribution custom origins should use secure TLS protocol versions (1.2 and above)', () => {
    const getTestRuleFixture = (items: string[]): NIST16xQueryResponse => {
      return {
        queryawsCloudfront: [
          {
            id: cuid(),
            origins: [
              {
                customOriginConfig: {
                  originSslProtocols: {
                    items,
                  },
                },
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST16xQueryResponse,
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

    test('No Security Issue when CloudFront distribution custom origins use secure TLS protocol versions 1.2 and above', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture(['TLSv1.2'])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when CloudFront distribution custom origins use secure TLS protocol versions older than 1.2', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture(['TLSv1.1'])
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 16.4 CloudFront distribution viewer certificate should use secure TLS protocol versions (1.2 and above)', () => {
    const getTestRuleFixture = (
      minimumProtocolVersion: string
    ): NIST16xQueryResponse => {
      return {
        queryawsCloudfront: [
          {
            id: cuid(),
            viewerCertificate: {
              minimumProtocolVersion,
            },
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST16xQueryResponse,
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

    test('No Security Issue when CloudFront distribution viewer certificate use secure TLS protocol versions TLSv1.2_2021 and above', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture('TLSv1.2_2021')
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when CloudFront distribution viewer certificate use secure TLS protocol versions TLSv1.2_2021 and above', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture('TLSv1.2_2019')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when CloudFront distribution viewer certificate use secure TLS protocol versions older than 1.2', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture('TLSv1.1_2016')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 16.5 ELB HTTPS listeners should use secure TLS protocol versions (1.2 and above)', () => {
    const getTestRuleFixture = (
      loadBalancerProtocol: string,
      sslCertificateId: string | null
    ): NIST16xQueryResponse => {
      return {
        queryawsElb: [
          {
            id: cuid(),
            listeners: [
              {
                loadBalancerProtocol,
                sslCertificateId,
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST16xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_165 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ELB HTTPS listeners have an SSL certificate configured', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture(
        'HTTPS',
        'arn:aws:acm:us-east-1:632941798677:certificate/add09e29-e7ea-4b4b-a8ca-706fb1e97d29'
      )
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when for ELB HTTP listeners', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture('HTTP', null)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when ELB HTTPS listeners not have a SSL certificate configured', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture('HTTPS', null)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 16.6 ELBv2 HTTPS listeners should use secure TLS protocol versions (1.2 and above)', () => {
    const getTestRuleFixture = (
      protocol: string,
      sslPolicy: string
    ): NIST16xQueryResponse => {
      return {
        queryawsAlb: [
          {
            id: cuid(),
            listeners: [
              {
                settings: {
                  protocol,
                  sslPolicy,
                },
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST16xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_166 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ELBv2 HTTPS listeners use secure TLS protocol versions 1.2 and above', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture(
        'HTTPS:443 arn:aws:elasticloadbalancing:us-east-1:632941798677:listener/app/autocloud-sandbox-ecs-alb/6abb1980e6ded2ce/e720d4895ea6678d',
        'ELBSecurityPolicy-2016-08'
      )
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when ELBv2 HTTP listeners use secure TLS protocol versions 1.2 and above', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture(
        'HTTP:80 arn:aws:elasticloadbalancing:us-east-1:632941798677:listener/app/autocloud-sandbox-ecs-alb/6abb1980e6ded2ce/e720d4895ea6678d',
        'ELBSecurityPolicy-2016-08'
      )
      await testRule(data, Result.PASS)
    })

    test('Security Issue when ELBv2 HTTPS listeners use a secure TLS protocol versions older than 1.2', async () => {
      const data: NIST16xQueryResponse = getTestRuleFixture(
        'HTTPS:443 arn:aws:elasticloadbalancing:us-east-1:632941798677:listener/app/autocloud-sandbox-ecs-alb/6abb1980e6ded2ce/e720d4895ea6678d',
        'ELBSecurityPolicy-2010-08'
      )
      await testRule(data, Result.FAIL)
    })
  })
})
