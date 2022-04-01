import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_NIST_800_53_61 from '../rules/aws-nist-800-53-rev4-6.1'
import Aws_NIST_800_53_64 from '../rules/aws-nist-800-53-rev4-6.4'
import Aws_NIST_800_53_65 from '../rules/aws-nist-800-53-rev4-6.5'
import Aws_NIST_800_53_66 from '../rules/aws-nist-800-53-rev4-6.6'
import Aws_NIST_800_53_68 from '../rules/aws-nist-800-53-rev4-6.8'
import Aws_NIST_800_53_69 from '../rules/aws-nist-800-53-rev4-6.9'
import Aws_NIST_800_53_612 from '../rules/aws-nist-800-53-rev4-6.12'
import Aws_NIST_800_53_613 from '../rules/aws-nist-800-53-rev4-6.13'

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

  describe('AWS NIST 6.1 CloudFront access logging should be enabled', () => {
    const getTestRuleFixture = (enabled: boolean): NIS6xQueryResponse => {
      return {
        queryawsCloudfront: [
          {
            id: cuid(),
            logging: {
              enabled,
            },
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_61 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when CloudFront access logging is enabled', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when CloudFront access logging is disabled', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 6.4 CloudTrail should have at least one CloudTrail trail set to a multi-region trail', () => {
    const getTestRuleFixture = (
      isMultiRegionTrail: string
    ): NIS6xQueryResponse => {
      return {
        queryawsAccount: [
          {
            id: cuid(),
            cloudtrail: [
              {
                isMultiRegionTrail,
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_64 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when CloudTrail have at least one CloudTrail trail set to a multi-region trail', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture('Yes')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when CloudTrail do not have any CloudTrail trail set to a multi-region trail', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture('No')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 6.5 CloudTrail trails should be configured to log data events for S3 buckets', () => {
    const getTestRuleFixture = (
      readWriteType: string,
      dataResources: DataResource[]
    ): NIS6xQueryResponse => {
      return {
        queryawsCloudtrail: [
          {
            id: cuid(),
            eventSelectors: [
              {
                readWriteType,
                dataResources,
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_65 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when CloudTrail trails is configured to log data events for S3 buckets', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture('All', [
        { type: 'AWS::S3::Object' },
      ])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when CloudTrail trails is not configured to log data events for S3 buckets', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture('All', [])
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 6.6 CloudTrail trails should be configured to log management events', () => {
    const getTestRuleFixture = (
      includeManagementEvents: boolean
    ): NIS6xQueryResponse => {
      return {
        queryawsCloudtrail: [
          {
            id: cuid(),
            eventSelectors: [
              {
                includeManagementEvents,
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_66 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when CloudTrail trails is configured to log management events', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when CloudTrail trails is not configured to log management events', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 6.8 Exactly one CloudTrail trail should monitor global services', () => {
    const getTestRuleFixture = (
      includeGlobalServiceEvents: string
    ): NIS6xQueryResponse => {
      return {
        queryawsAccount: [
          {
            id: cuid(),
            cloudtrail: [
              {
                includeGlobalServiceEvents: 'Yes',
              },
              {
                includeGlobalServiceEvents,
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_68 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Exactly one CloudTrail trail is monitor global services', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture('No')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when more that one CloudTrail trail is monitor global services', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture('Yes')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 6.9 Load balancer access logging should be enabled', () => {
    const getTestRuleAFixture = (
      accessLogs: string
    ): NIS6xQueryResponse => {
      return {
        queryawsElb: [
          {
            id: cuid(),
            accessLogs,
          },
        ],
      }
    }

    const getTestRuleBFixture = (
      accessLogsEnabled: string
    ): NIS6xQueryResponse => {
      return {
        queryawsAlb: [
          {
            id: cuid(),
            accessLogsEnabled,
          },
        ],
      }
    }

    const testRule = async (
      data: NIS6xQueryResponse,
      expectedResult: Result,
      rule?: any
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(rule as Rule, {
        ...data,
      })

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }


    describe('queryawsElb query:', () => {
      let targetElbRule: Rule
      beforeAll(() => {
        const { queries, ...ruleMetadata } = Aws_NIST_800_53_69
        const query = queries.shift()
        targetElbRule = {
          ...ruleMetadata,
          ...query,
        } as Rule
      })

      test('No Security Issue when Load balancer (ELB) access logging is enabled', async () => {
        const data: NIS6xQueryResponse = getTestRuleAFixture('Enabled')
        await testRule(data, Result.PASS, targetElbRule)
      })

      test('Security Issue when Load balancer (ELB) access logging is disabled', async () => {
        const data: NIS6xQueryResponse = getTestRuleAFixture('Disabled')
        await testRule(data, Result.FAIL, targetElbRule)
      })
    })

    describe('queryawsAlb query:', () => {
      let targetAlbRule: Rule
      beforeAll(() => {
        const { queries, ...ruleMetadata } = Aws_NIST_800_53_69
        const query = queries.shift()
        targetAlbRule = {
          ...ruleMetadata,
          ...query,
        } as Rule
      })

      test('No Security Issue when Load balancer (ELBv2) access logging is enabled', async () => {
        const data: NIS6xQueryResponse = getTestRuleBFixture('Yes')
        await testRule(data, Result.PASS, targetAlbRule)
      })

      test('Security Issue when Load balancer (ELBv2) access logging is disabled', async () => {
        const data: NIS6xQueryResponse = getTestRuleBFixture('No')
        await testRule(data, Result.FAIL, targetAlbRule)
      })
    })
  })

  describe('AWS NIST 6.12 S3 bucket object-level logging for read events should be enabled', () => {
    const getTestRuleFixture = (
      includeManagementEvents: boolean,
      readWriteType: string,
      dataResources: DataResource[]
    ): NIS6xQueryResponse => {
      return {
        queryawsAccount: [
          {
            id: cuid(),
            cloudtrail: [
              {
                eventSelectors: [
                  {
                    includeManagementEvents,
                    readWriteType,
                    dataResources,
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
      data: NIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_612 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when S3 bucket object-level logging for read events is enabled', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(true, 'ReadOnly', [
        { type: 'AWS::S3::Object' },
      ])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when S3 bucket object-level logging for read events is not enabled', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(true, 'ReadOnly', [])
      await testRule(data, Result.PASS)
    })
  })

  describe('AWS NIST 6.13 S3 bucket object-level logging for write events should be enabled', () => {
    const getTestRuleFixture = (
      includeManagementEvents: boolean,
      readWriteType: string,
      dataResources: DataResource[]
    ): NIS6xQueryResponse => {
      return {
        queryawsAccount: [
          {
            id: cuid(),
            cloudtrail: [
              {
                eventSelectors: [
                  {
                    includeManagementEvents,
                    readWriteType,
                    dataResources,
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
      data: NIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_613 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when S3 bucket object-level logging for write events is enabled', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(true, 'WriteOnly', [
        { type: 'AWS::S3::Object' },
      ])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when S3 bucket object-level logging for write events is not enabled', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(true, 'WriteOnly', [])
      await testRule(data, Result.PASS)
    })
  })
})
