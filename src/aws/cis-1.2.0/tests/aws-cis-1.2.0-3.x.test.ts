import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Aws_CIS_120_31 from '../rules/aws-cis-1.2.0-3.1'
import Aws_CIS_120_32 from '../rules/aws-cis-1.2.0-3.2'
import Aws_CIS_120_310 from '../rules/aws-cis-1.2.0-3.10'
import Aws_CIS_120_311 from '../rules/aws-cis-1.2.0-3.11'
import Aws_CIS_120_312 from '../rules/aws-cis-1.2.0-3.12'
import Aws_CIS_120_313 from '../rules/aws-cis-1.2.0-3.13'
import Aws_CIS_120_314 from '../rules/aws-cis-1.2.0-3.14'

const Aws_CIS_120_31_Filter_Pattern =
  '{ ($.errorCode =  "UnauthorizedOperation") || ($.errorCode = "AccessDenied") }'
const Aws_CIS_120_32_Filter_Pattern =
  '{ ($.errorCode = "ConsoleLogin") || ($.additionalEventData.MFAUsed != "Yes")  }'
const Aws_CIS_120_310_Filter_Pattern =
  // eslint-disable-next-line max-len
  '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }'
const Aws_CIS_120_311_Filter_Pattern =
  // eslint-disable-next-line max-len
  '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }'
const Aws_CIS_120_312_Filter_Pattern =
  // eslint-disable-next-line max-len
  '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'
const Aws_CIS_120_313_Filter_Pattern =
  // eslint-disable-next-line max-len
  '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }'
const Aws_CIS_120_314_Filter_Pattern =
  // eslint-disable-next-line max-len
  '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'

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
export interface CIS3xQueryResponse {
  queryawsCloudtrail: QueryawsCloudtrailEntity[]
}

describe('CIS Amazon Web Services Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine('aws', 'CIS')
  })

  const get3xValidResponse = (
    metricFilterPattern: string
  ): CIS3xQueryResponse => ({
    queryawsCloudtrail: [
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
                  '{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }',
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
  })
  describe('AWS CIS 3.1 Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)', () => {
    const test31Rule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_31 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get3xValidResponse(Aws_CIS_120_31_Filter_Pattern)
      await test31Rule(data, Result.PASS)
    })

    test('Security Issue when isLogging is false', async () => {
      const data = get3xValidResponse(Aws_CIS_120_31_Filter_Pattern)
      data.queryawsCloudtrail[0].status.isLogging = false
      await test31Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get3xValidResponse(Aws_CIS_120_31_Filter_Pattern)
      data.queryawsCloudtrail[0].eventSelectors[0].readWriteType = 'dummy'
      await test31Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get3xValidResponse(Aws_CIS_120_31_Filter_Pattern)
      data.queryawsCloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await test31Rule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern just contains one error code', async () => {
      const data = get3xValidResponse(
        '{ ($.errorCode =  "UnauthorizedOperation") }'
      )
      await test31Rule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get3xValidResponse(Aws_CIS_120_31_Filter_Pattern)
      data.queryawsCloudtrail[0].cloudwatchLog[0].cloudwatch[0].sns[0].subscriptions =
        []
      await test31Rule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 3.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)', () => {
    const test32Rule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_32 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get3xValidResponse(Aws_CIS_120_32_Filter_Pattern)
      await test32Rule(data, Result.PASS)
    })

    test('Security Issue when isLogging is false', async () => {
      const data = get3xValidResponse(Aws_CIS_120_32_Filter_Pattern)
      data.queryawsCloudtrail[0].status.isLogging = false
      await test32Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get3xValidResponse(Aws_CIS_120_32_Filter_Pattern)
      data.queryawsCloudtrail[0].eventSelectors[0].readWriteType = 'dummy'
      await test32Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get3xValidResponse(Aws_CIS_120_32_Filter_Pattern)
      data.queryawsCloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await test32Rule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern just contains one error code', async () => {
      const data = get3xValidResponse('{ ($.errorCode = "ConsoleLogin") }')
      await test32Rule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get3xValidResponse(Aws_CIS_120_32_Filter_Pattern)
      data.queryawsCloudtrail[0].cloudwatchLog[0].cloudwatch[0].sns[0].subscriptions =
        []
      await test32Rule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 3.10 Ensure a log metric filter and alarm exist for security group changes (Scored)', () => {
    const test310Rule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_310 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get3xValidResponse(Aws_CIS_120_310_Filter_Pattern)
      await test310Rule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get3xValidResponse(Aws_CIS_120_310_Filter_Pattern)
      data.queryawsCloudtrail[0].status.isLogging = false
      await test310Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get3xValidResponse(Aws_CIS_120_310_Filter_Pattern)
      data.queryawsCloudtrail[0].eventSelectors[0].readWriteType = 'dummy'
      await test310Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get3xValidResponse(Aws_CIS_120_310_Filter_Pattern)
      data.queryawsCloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await test310Rule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get3xValidResponse('dummy metric filter value')
      await test310Rule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get3xValidResponse(Aws_CIS_120_310_Filter_Pattern)
      data.queryawsCloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await test310Rule(data, Result.FAIL)
    })
  })
  describe('AWS CIS 3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)', () => {
    const test311Rule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_311 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get3xValidResponse(Aws_CIS_120_311_Filter_Pattern)
      await test311Rule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get3xValidResponse(Aws_CIS_120_311_Filter_Pattern)
      data.queryawsCloudtrail[0].status.isLogging = false
      await test311Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get3xValidResponse(Aws_CIS_120_310_Filter_Pattern)
      data.queryawsCloudtrail[0].eventSelectors[0].readWriteType = 'dummy'
      await test311Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get3xValidResponse(Aws_CIS_120_311_Filter_Pattern)
      data.queryawsCloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await test311Rule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get3xValidResponse('dummy metric filter value')
      await test311Rule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get3xValidResponse(Aws_CIS_120_311_Filter_Pattern)
      data.queryawsCloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await test311Rule(data, Result.FAIL)
    })
  })
  describe('AWS CIS 3.12 Ensure a log metric filter and alarm exist for changes to network gateways (Scored)', () => {
    const test312Rule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_312 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get3xValidResponse(Aws_CIS_120_312_Filter_Pattern)
      await test312Rule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get3xValidResponse(Aws_CIS_120_312_Filter_Pattern)
      data.queryawsCloudtrail[0].status.isLogging = false
      await test312Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get3xValidResponse(Aws_CIS_120_312_Filter_Pattern)
      data.queryawsCloudtrail[0].eventSelectors[0].readWriteType = 'dummy'
      await test312Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get3xValidResponse(Aws_CIS_120_312_Filter_Pattern)
      data.queryawsCloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await test312Rule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get3xValidResponse('dummy metric filter value')
      await test312Rule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get3xValidResponse(Aws_CIS_120_312_Filter_Pattern)
      data.queryawsCloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await test312Rule(data, Result.FAIL)
    })
  })
  describe('AWS CIS 3.13 Ensure a log metric filter and alarm exist for route table changes (Scored)', () => {
    const test313Rule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_313 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get3xValidResponse(Aws_CIS_120_313_Filter_Pattern)
      await test313Rule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get3xValidResponse(Aws_CIS_120_313_Filter_Pattern)
      data.queryawsCloudtrail[0].status.isLogging = false
      await test313Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get3xValidResponse(Aws_CIS_120_313_Filter_Pattern)
      data.queryawsCloudtrail[0].eventSelectors[0].readWriteType = 'dummy'
      await test313Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get3xValidResponse(Aws_CIS_120_313_Filter_Pattern)
      data.queryawsCloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await test313Rule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get3xValidResponse('dummy metric filter value')
      await test313Rule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get3xValidResponse(Aws_CIS_120_313_Filter_Pattern)
      data.queryawsCloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await test313Rule(data, Result.FAIL)
    })
  })
  describe('AWS CIS 3.14 Ensure a log metric filter and alarm exist for VPC changes (Scored)', () => {
    const test314Rule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_314 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get3xValidResponse(Aws_CIS_120_314_Filter_Pattern)
      await test314Rule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get3xValidResponse(Aws_CIS_120_314_Filter_Pattern)
      data.queryawsCloudtrail[0].status.isLogging = false
      await test314Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get3xValidResponse(Aws_CIS_120_314_Filter_Pattern)
      data.queryawsCloudtrail[0].eventSelectors[0].readWriteType = 'dummy'
      await test314Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get3xValidResponse(Aws_CIS_120_314_Filter_Pattern)
      data.queryawsCloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await test314Rule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get3xValidResponse('dummy metric filter value')
      await test314Rule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get3xValidResponse(Aws_CIS_120_314_Filter_Pattern)
      data.queryawsCloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await test314Rule(data, Result.FAIL)
    })
  })
})
