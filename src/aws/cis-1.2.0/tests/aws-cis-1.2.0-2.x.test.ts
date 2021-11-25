import cuid from 'cuid'
import CloudGraph, { Rule, Engine } from '@cloudgraph/sdk'

import Aws_CIS_120_21 from '../rules/aws-cis-1.2.0-2.1'

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

    test('Should pass when a trail has set multi region as true with all read-write type and include management events true', async () => {
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
})
