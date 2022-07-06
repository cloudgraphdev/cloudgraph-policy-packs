import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Aws_NIST_800_53_31 from '../rules/aws-nist-800-53-rev4-3.1'
import Aws_NIST_800_53_32 from '../rules/aws-nist-800-53-rev4-3.2'
import Aws_NIST_800_53_33 from '../rules/aws-nist-800-53-rev4-3.3'
import Aws_NIST_800_53_34 from '../rules/aws-nist-800-53-rev4-3.4'
import Aws_NIST_800_53_35 from '../rules/aws-nist-800-53-rev4-3.5'
import Aws_NIST_800_53_36 from '../rules/aws-nist-800-53-rev4-3.6'
import Aws_NIST_800_53_37 from '../rules/aws-nist-800-53-rev4-3.7'

export interface SseDescription {
  status?: string | null
  sseType?: string | null
}

export interface QueryawsSqs {
  id: string
  kmsMasterKeyId?: string | null
}

export interface QueryawsS3 {
  id: string
  encrypted: string
}

export interface QueryawsRdsDbInstance {
  id: string
  encrypted: boolean
}

export interface QueryawsEbs {
  id: string
  encrypted: boolean
}
export interface QueryawsDynamoDbTable {
  id: string
  sseDescription?: SseDescription
}
export interface QueryawsCloudwatchLog {
  id: string
  kmsKeyId?: string | null
}
export interface QueryawsCloudtrail {
  id: string
  kmsKeyId?: string | null
}
export interface NIS3xQueryResponse {
  queryawsCloudtrail?: QueryawsCloudtrail[]
  queryawsCloudwatchLog?: QueryawsCloudwatchLog[]
  queryawsDynamoDbTable?: QueryawsDynamoDbTable[]
  queryawsEbs?: QueryawsEbs[]
  queryawsRdsDbInstance?: QueryawsRdsDbInstance[]
  queryawsS3?: QueryawsS3[]
  queryawsSqs?: QueryawsSqs[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'NIST')
  })

  describe('AWS NIST 3.1 CloudTrail log files should be encrypted with customer managed KMS keys', () => {
    const getTestRuleFixture = (
      kmsKeyId: string | null
    ): NIS3xQueryResponse => {
      return {
        queryawsCloudtrail: [
          {
            id: cuid(),
            kmsKeyId,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_31 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when CloudTrail log files are encrypted with customer managed KMS keys', async () => {
      const data: NIS3xQueryResponse = getTestRuleFixture(cuid())
      await testRule(data, Result.PASS)
    })

    test('Security Issue when CloudTrail log files are not encrypted with customer managed KMS keys', async () => {
      const data: NIS3xQueryResponse = getTestRuleFixture(null)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 3.2 CloudWatch log groups should be encrypted with customer managed KMS keys', () => {
    const getTestRuleFixture = (
      kmsKeyId: string | null
    ): NIS3xQueryResponse => {
      return {
        queryawsCloudwatchLog: [
          {
            id: cuid(),
            kmsKeyId,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_32 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when CloudWatch log groups are encrypted with customer managed KMS keys', async () => {
      const data: NIS3xQueryResponse = getTestRuleFixture(cuid())
      await testRule(data, Result.PASS)
    })

    test('Security Issue when CloudWatch log groups are not encrypted with customer managed KMS keys', async () => {
      const data: NIS3xQueryResponse = getTestRuleFixture(null)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 3.3 DynamoDB tables should be encrypted with AWS or customer managed KMS keys', () => {
    const getTestRuleFixture = (
      status: string | null,
      sseType: string | null
    ): NIS3xQueryResponse => {
      return {
        queryawsDynamoDbTable: [
          {
            id: cuid(),
            sseDescription: {
              status,
              sseType,
            },
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_33 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when DynamoDB tables is encrypted with AWS or customer managed KMS keys', async () => {
      const data: NIS3xQueryResponse = getTestRuleFixture('ENABLED', 'KMS')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when DynamoDB tables encryption is disabled for AWS or customer managed KMS keys', async () => {
      const data: NIS3xQueryResponse = getTestRuleFixture('DISABLED', 'KMS')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when DynamoDB tables is not encrypted with AWS or customer managed KMS keys', async () => {
      const data: NIS3xQueryResponse = getTestRuleFixture(null, null)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 3.4 EBS volume encryption should be enabled', () => {
    const getTestRuleFixture = (encrypted: boolean): NIS3xQueryResponse => {
      return {
        queryawsEbs: [
          {
            id: cuid(),
            encrypted,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_34 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when EBS volume encryption is enabled', async () => {
      const data: NIS3xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when EBS volume encryption is not enabled', async () => {
      const data: NIS3xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 3.5 RDS instances should be encrypted', () => {
    const getTestRuleFixture = (encrypted: boolean): NIS3xQueryResponse => {
      return {
        queryawsRdsDbInstance: [
          {
            id: cuid(),
            encrypted,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_35 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when RDS instances are encrypted', async () => {
      const data: NIS3xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when RDS instances are not encrypted', async () => {
      const data: NIS3xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 3.6 S3 bucket server-side encryption should be enabled', () => {
    const getTestRuleFixture = (encrypted: string): NIS3xQueryResponse => {
      return {
        queryawsS3: [
          {
            id: cuid(),
            encrypted,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_36 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when S3 bucket server-side encryption is enabled', async () => {
      const data: NIS3xQueryResponse = getTestRuleFixture('Yes')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when S3 bucket server-side encryption is not enabled', async () => {
      const data: NIS3xQueryResponse = getTestRuleFixture('No')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 3.7 SQS queue server-side encryption should be enabled with KMS keys', () => {
    const getTestRuleFixture = (
      kmsMasterKeyId: string | null
    ): NIS3xQueryResponse => {
      return {
        queryawsSqs: [
          {
            id: cuid(),
            kmsMasterKeyId,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_37 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when SQS queue server-side encryption is enabled with KMS keys', async () => {
      const data: NIS3xQueryResponse = getTestRuleFixture(cuid())
      await testRule(data, Result.PASS)
    })

    test('Security Issue when SQS queue server-side encryption is not enabled with KMS keys', async () => {
      const data: NIS3xQueryResponse = getTestRuleFixture(null)
      await testRule(data, Result.FAIL)
    })
  })
})
