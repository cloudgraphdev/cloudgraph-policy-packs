import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_Cloudwatch_1 from '../rules/pci-dss-3.2.1-cloudwatch-check-1'

const Filter_Pattern =
  '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'

export interface SubscriptionsEntity {
  arn: string
}
export interface SnsEntity {
  arn: string
  subscriptions?: SubscriptionsEntity[] | null
}
export interface CloudwatchEntity {
  arn: string
  actions?: string[] | null
  sns: SnsEntity[]
  metric: string
}
export interface MetricTransformation {
  metricName: string
}
export interface MetricFiltersEntity {
  id: string
  filterName: string
  filterPattern: string
  metricTransformations: MetricTransformation[]
}
export interface CloudwatchLogEntity {
  arn: string
  metricFilters: MetricFiltersEntity[]
  cloudwatch: CloudwatchEntity[]
}
export interface EventSelectorsEntity {
  id: string
  readWriteType: string
  includeManagementEvents: boolean
}
export interface Status {
  isLogging: boolean
}
export interface QueryawsCloudtrailEntity {
  id: string
  isMultiRegionTrail: string
  status: Status
  eventSelectors: EventSelectorsEntity[]
  cloudwatchLog: CloudwatchLogEntity[]
}

export interface QueryAccount {
  id: string
  cloudtrail: QueryawsCloudtrailEntity[]
}

export interface QueryResponse {
  queryawsAccount: QueryAccount[]
}

const getValidResponse = (metricFilterPattern: string): QueryResponse => ({
  queryawsAccount: [
    {
      id: cuid(),
      cloudtrail: [
        {
          id: 'arn:aws:cloudtrail:us-east-2:111111111111:trail/snsTest',
          isMultiRegionTrail: 'Yes',
          status: {
            isLogging: true,
          },
          eventSelectors: [
            {
              id: 'ckxysdl0u000osf7k0bmz41n8',
              readWriteType: 'All',
              includeManagementEvents: true,
            },
          ],
          cloudwatchLog: [
            {
              arn: 'arn:aws:logs:us-east-1:111111111111:log-group:aws-cloudtrail-logs-111111111111-11111111:*',
              metricFilters: [
                {
                  id: 'ckxysdl0s000ksf7kci3q4obi',
                  filterName: 'KmsDeletion',
                  filterPattern:
                    '{($.eventSource = kms.test.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }',
                  metricTransformations: [
                    {
                      metricName: 'KmsDeletionCount',
                    },
                  ],
                },
                {
                  id: 'ckxysdl0s000ksf7kci3q4obi',
                  filterName: 'DummyName',
                  filterPattern: metricFilterPattern,
                  metricTransformations: [
                    {
                      metricName: 'DummyNameCount',
                    },
                  ],
                },
              ],
              cloudwatch: [
                {
                  metric: 'KmsDeletionCount',
                  arn: 'arn:aws:cloudwatch:us-east-1:111111111111:alarm:KmsDeletionAlarm',
                  actions: ['arn:aws:sns:us-east-1:111111111111:...'],
                  sns: [
                    {
                      arn: 'arn:aws:sns:us-east-1:111111111111:...',
                      subscriptions: [
                        {
                          arn: 'arn:aws:sns:...',
                        },
                      ],
                    },
                  ],
                },
                {
                  metric: 'DummyNameCount',
                  arn: 'arn:aws:cloudwatch:us-east-1:111111111111:alarm:DummyAlarm',
                  actions: ['arn:aws:sns:us-east-1:111111111111:...'],
                  sns: [
                    {
                      arn: 'arn:aws:sns:us-east-1:111111111111:...',
                      subscriptions: [
                        {
                          arn: 'arn:aws:sns:us-east-1:111111111111:...:11111111-1111-1111-1111-111111111111',
                        },
                      ],
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    },
  ],
})

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'PCI',
    })
  })

  describe('Cloudwatch Check 1: A log metric filter and alarm should exist for usage of the "root" user', () => {
    const test33Rule = async (
      data: QueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Cloudwatch_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('Should failed when no cloudtrail data is found', async () => {
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            cloudtrail: [],
          },
        ],
      }
      await test33Rule(data, Result.FAIL)
    })

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = getValidResponse(Filter_Pattern)
      await test33Rule(data, Result.PASS)
    })

    test('Security Issue when isLogging is false', async () => {
      const data = getValidResponse(Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await test33Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = getValidResponse(Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await test33Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = getValidResponse(Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await test33Rule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern just contains one condition', async () => {
      const data = getValidResponse(
        '{ $.userIdentity.type = "Root" || $.userIdentity.invokedBy NOT EXISTS }'
      )
      await test33Rule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = getValidResponse(Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await test33Rule(data, Result.FAIL)
    })
  })
})
