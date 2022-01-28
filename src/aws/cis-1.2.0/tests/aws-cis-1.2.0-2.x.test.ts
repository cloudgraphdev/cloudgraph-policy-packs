import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_CIS_120_21 from '../rules/aws-cis-1.2.0-2.1'
import Aws_CIS_120_22 from '../rules/aws-cis-1.2.0-2.2'
import Aws_CIS_120_24 from '../rules/aws-cis-1.2.0-2.4'
import Aws_CIS_120_26 from '../rules/aws-cis-1.2.0-2.6'
import Aws_CIS_120_27 from '../rules/aws-cis-1.2.0-2.7'
import Aws_CIS_120_28 from '../rules/aws-cis-1.2.0-2.8'
import Aws_CIS_120_29 from '../rules/aws-cis-1.2.0-2.9'

describe('CIS Amazon Web Services Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine('aws', 'CIS')
  })
  describe('AWS CIS 2.1 Ensure CloudTrail is enabled in all regions', () => {
    test('Should pass when a trail has set multi region as false', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            isMultiRegionTrail: 'No',
            eventSelectors: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_21 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass when a trail has set multi region as true with all read-write type and include management events false', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            isMultiRegionTrail: 'Yes',
            eventSelectors: [
              {
                readWriteType: 'All',
                includeManagementEvents: false,
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_21 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when a trail has set multi region as true with all read-write type and include management events true', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            isMultiRegionTrail: 'Yes',
            eventSelectors: [
              {
                readWriteType: 'All',
                includeManagementEvents: true,
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_21 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('AWS CIS 2.2 Ensure CloudTrail log file validation is enabled', () => {
    test('Should pass when a trail has log file validation enabled', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            logFileValidationEnabled: 'Yes',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_22 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when a trail has log file validation disabled', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            logFileValidationEnabled: 'No',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_22 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('AWS CIS 2.4 Ensure CloudTrail trails are integrated with CloudWatch Logs', () => {
    test('Should pass when a trail has cloudwatch logs integrated with a delivery date no more than a day', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            cloudWatchLogsLogGroupArn: cuid(),
            status: {
              latestCloudWatchLogsDeliveryTime: new Date().toISOString(),
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_24 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when a trail has cloudwatch logs integrated with a delivery date more than a day', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            cloudWatchLogsLogGroupArn: cuid(),
            status: {
              latestCloudWatchLogsDeliveryTime: '2021-11-20T16:18:21.724Z',
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_24 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
    test('Should pass when a trail does not have cloudwatch logs integrated', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            cloudWatchLogsLogGroupArn: null,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_24 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('AWS CIS 2.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket', () => {
    test("Should pass when a trail's bucket has access logging enabled", async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            s3: [
              {
                logging: 'Enabled',
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_26 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test("Should fail when a trail's bucket has access logging disabled", async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            s3: [
              {
                logging: 'Disabled',
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_26 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('AWS CIS 2.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs', () => {
    test('Should pass when cloudtrail logs are encrypted using a KMS key', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            kmsKeyId: cuid(),
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_27 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when cloudtrail logs are not encrypted', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            kmsKeyId: null,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_27 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('AWS CIS 2.8 Ensure rotation for customer created CMKs is enabled (Scored)', () => {
    test('Should pass when rotation is enabled with customer as a manager', async () => {
      const data = {
        queryawsKms: [
          {
            id: cuid(),
            keyManager: 'CUSTOMER',
            keyRotationEnabled: 'Yes',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_28 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass when rotation is enabled with AWS as a manager', async () => {
      const data = {
        queryawsKms: [
          {
            id: cuid(),
            keyManager: 'AWS',
            keyRotationEnabled: 'Yes',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_28 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass when rotation is disabled with customer as a manager', async () => {
      const data = {
        queryawsKms: [
          {
            id: cuid(),
            keyManager: 'CUSTOMER',
            keyRotationEnabled: 'No',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_28 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when rotation is disabled with AWS as a manager', async () => {
      const data = {
        queryawsKms: [
          {
            id: cuid(),
            keyManager: 'AWS',
            keyRotationEnabled: 'No',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_28 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('AWS CIS 2.9 Ensure VPC flow logging is enabled in all VPCs (Scored)', () => {
    test('Should pass when flow logging is enabled for each VPC', async () => {
      const data = {
        queryawsVpc: [
          {
            id: cuid(),
            flowLogs: [
              {
                resourceId: cuid(),
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_29 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when flow logging is disabled on one VPC', async () => {
      const data = {
        queryawsVpc: [
          {
            id: cuid(),
            flowLogs: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_29 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })
})