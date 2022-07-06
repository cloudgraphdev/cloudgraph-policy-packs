import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_NIST_800_53_61 from '../rules/aws-nist-800-53-rev4-6.1'
import Aws_NIST_800_53_62 from '../rules/aws-nist-800-53-rev4-6.2'
import Aws_NIST_800_53_63 from '../rules/aws-nist-800-53-rev4-6.3'
import Aws_NIST_800_53_64 from '../rules/aws-nist-800-53-rev4-6.4'
import Aws_NIST_800_53_65 from '../rules/aws-nist-800-53-rev4-6.5'
import Aws_NIST_800_53_66 from '../rules/aws-nist-800-53-rev4-6.6'
import Aws_NIST_800_53_67 from '../rules/aws-nist-800-53-rev4-6.7'
import Aws_NIST_800_53_68 from '../rules/aws-nist-800-53-rev4-6.8'
import Aws_NIST_800_53_69 from '../rules/aws-nist-800-53-rev4-6.9'
import Aws_NIST_800_53_610 from '../rules/aws-nist-800-53-rev4-6.10'
import Aws_NIST_800_53_611 from '../rules/aws-nist-800-53-rev4-6.11'
import Aws_NIST_800_53_612 from '../rules/aws-nist-800-53-rev4-6.12'
import Aws_NIST_800_53_613 from '../rules/aws-nist-800-53-rev4-6.13'
import Aws_NIST_800_53_614 from '../rules/aws-nist-800-53-rev4-6.14'
import { initRuleEngine } from '../../../utils/test'

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

export interface Status {
  isLogging?: boolean
  latestCloudWatchLogsDeliveryTime?: string
}

export interface Cloudtrail {
  isMultiRegionTrail?: string
  eventSelectors?: EventSelector[]
  includeGlobalServiceEvents?: string
  status?: Status
}

export interface S3 {
  logging: string
}

export interface FlowLog {
  logStatus: string
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
  logFileValidationEnabled?: string
  cloudWatchLogsLogGroupArn?: string
  s3?: S3[]
  status?: Status
}

export interface QueryawsAlb {
  id: string
  accessLogsEnabled: string
}

export interface QueryawsElb {
  id: string
  accessLogs: string
}

export interface QueryawsS3 {
  id: string
  logging: string
}

export interface QueryawsVpc {
  id: string
  flowLog: FlowLog[]
}
export interface NIS6xQueryResponse {
  queryawsCloudfront?: QueryawsCloudfront[]
  queryawsAccount?: QueryawsAccount[]
  queryawsCloudtrail?: QueryawsCloudtrail[]
  queryawsAlb?: QueryawsAlb[]
  queryawsElb?: QueryawsElb[]
  queryawsS3?: QueryawsS3[]
  queryawsVpc?: QueryawsVpc[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'NIST')
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

  describe('AWS NIST 6.2 CloudTrail log file validation should be enabled', () => {
    const getTestRuleFixture = (
      logFileValidationEnabled: string
    ): NIS6xQueryResponse => {
      return {
        queryawsCloudtrail: [
          {
            id: cuid(),
            logFileValidationEnabled,
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
        Aws_NIST_800_53_62 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when a trail has log file validation enabled', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture('Yes')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when a trail has log file validation disabled', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture('No')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 6.3 CloudTrail should be enabled in all regions', () => {
    const getTestRuleFixture = (
      isMultiRegionTrail: string,
      isLogging: boolean,
      readWriteType: string,
      includeManagementEvents: boolean
    ): NIS6xQueryResponse => {
      return {
        queryawsAccount: [
          {
            id: cuid(),
            cloudtrail: [
              {
                isMultiRegionTrail,
                status: {
                  isLogging,
                },
                eventSelectors: [
                  {
                    readWriteType,
                    includeManagementEvents,
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
        Aws_NIST_800_53_63 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when a trail has set IsMultiRegionTrail and isLogging as true with at least one Event Selector with IncludeManagementEvents set to true and ReadWriteType set to All', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(
        'Yes',
        true,
        'All',
        true
      )
      await testRule(data, Result.PASS)
    })

    test('Security Issue when a trail has set IsMultiRegionTrail is set to false', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(
        'No',
        true,
        'All',
        true
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when a trail has set isLogging is set to false', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(
        'Yes',
        false,
        'All',
        true
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when a trail has set multi region as true with all read-write type and include management events false', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(
        'Yes',
        true,
        'All',
        false
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there not are any trail', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(
        'Yes',
        true,
        'All',
        true
      )
      const account = data.queryawsAccount?.[0] as QueryawsAccount
      account.cloudtrail = []
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
      includeManagementEvents: boolean,
      readWriteType: string,
      dataResources: DataResource[]
    ): NIS6xQueryResponse => {
      return {
        queryawsCloudtrail: [
          {
            id: cuid(),
            eventSelectors: [
              {
                includeManagementEvents,
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
      const data: NIS6xQueryResponse = getTestRuleFixture(true, 'All', [
        { type: 'AWS::S3::Object' },
      ])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when CloudTrail trails is not configured to log data events for S3 buckets', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(true, 'All', [])
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

  describe('AWS NIST 6.7 CloudTrail trails should have CloudWatch log integration enabled', () => {
    const getTestRuleFixture = (
      cloudWatchLogsLogGroupArn: string,
      latestCloudWatchLogsDeliveryTime: string
    ): NIS6xQueryResponse => {
      return {
        queryawsCloudtrail: [
          {
            id: cuid(),
            cloudWatchLogsLogGroupArn,
            status: {
              latestCloudWatchLogsDeliveryTime
            }
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
        Aws_NIST_800_53_67 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when a trail has cloudwatch logs integrated with a delivery date no more than a day', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(cuid(), new Date().toISOString())
      await testRule(data, Result.PASS)
    })

    test('Security Issue when a trail has cloudwatch logs integrated with a delivery date more than a day', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture(cuid(), '2021-11-20T16:18:21.724Z')
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
    const getTestRuleAFixture = (accessLogs: string): NIS6xQueryResponse => {
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

  describe('AWS NIST 6.10 S3 bucket access logging should be enabled', () => {
    const getTestRuleFixture = (logging: string): NIS6xQueryResponse => {
      return {
        queryawsS3: [
          {
            id: cuid(),
            logging,
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
        Aws_NIST_800_53_610 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when S3 bucket access logging is enabled', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture('Enabled')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when S3 bucket access logging is disabled', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture('Disabled')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 6.11 S3 bucket access logging should be enabled on S3 buckets that store CloudTrail log files', () => {
    const getTestRuleFixture = (logging: string): NIS6xQueryResponse => {
      return {
        queryawsCloudtrail: [
          {
            id: cuid(),
            s3: [
              {
                logging,
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
        Aws_NIST_800_53_611 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when a trail bucket has access logging enabled', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture('Enabled')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when a trail bucket has access logging disabled', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture('Disabled')
      await testRule(data, Result.FAIL)
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
      await testRule(data, Result.FAIL)
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
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 6.14 VPC flow logging should be enabled', () => {
    const getTestRuleFixture = (logStatus: string): NIS6xQueryResponse => {
      return {
        queryawsVpc: [
          {
            id: cuid(),
            flowLog: [
              {
                logStatus,
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
        Aws_NIST_800_53_614 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when flow logging is enabled for each VPC', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture('ACTIVE')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when flow logging is disabled on one VPC', async () => {
      const data: NIS6xQueryResponse = getTestRuleFixture('')
      const vpc = data.queryawsVpc?.[0] as QueryawsVpc
      vpc.flowLog = []
      await testRule(data, Result.FAIL)
    })
  })
})
