import cuid from 'cuid'
import CloudGraph, { Rule, Engine } from '@cloudgraph/sdk'

import Aws_CIS_120_21 from '../rules/aws-cis-1.2.0-2.1'
import Aws_CIS_120_22 from '../rules/aws-cis-1.2.0-2.2'
import Aws_CIS_120_24 from '../rules/aws-cis-1.2.0-2.4'

describe('CIS Amazon Web Services Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine()
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

      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
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

      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
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

      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
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

      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
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

      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
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

      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
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

      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
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

      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })
})
