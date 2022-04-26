import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_NIST_800_53_71 from '../rules/aws-nist-800-53-rev4-7.1'
import Aws_NIST_800_53_72 from '../rules/aws-nist-800-53-rev4-7.2'
import Aws_NIST_800_53_73 from '../rules/aws-nist-800-53-rev4-7.3'
import Aws_NIST_800_53_74 from '../rules/aws-nist-800-53-rev4-7.4'
import Aws_NIST_800_53_75 from '../rules/aws-nist-800-53-rev4-7.5'
import Aws_NIST_800_53_77 from '../rules/aws-nist-800-53-rev4-7.7'
import Aws_NIST_800_53_78 from '../rules/aws-nist-800-53-rev4-7.8'
import Aws_NIST_800_53_79 from '../rules/aws-nist-800-53-rev4-7.9'
import Aws_NIST_800_53_710 from '../rules/aws-nist-800-53-rev4-7.10'
import Aws_NIST_800_53_711 from '../rules/aws-nist-800-53-rev4-7.11'
import Aws_NIST_800_53_712 from '../rules/aws-nist-800-53-rev4-7.12'
import Aws_NIST_800_53_713 from '../rules/aws-nist-800-53-rev4-7.13'
import Aws_NIST_800_53_714 from '../rules/aws-nist-800-53-rev4-7.14'

const Aws_NIST_800_53_72_Filter_Pattern =
  '{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy") || ($.eventName = "UpdateOrganizationalUnit")) }'
const Aws_NIST_800_53_73_Filter_Pattern =
  '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }'
const Aws_NIST_800_53_74_Filter_Pattern =
  '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'
const Aws_NIST_800_53_75_Filter_Pattern =
  '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }'
const Aws_NIST_800_53_77_Filter_Pattern =
  '{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy)}'
const Aws_NIST_800_53_78_Filter_Pattern =
  '{ ($.eventName = ConsoleLogin1) && ($.errorMessage = "Failed authentication") }'
const Aws_NIST_800_53_79_Filter_Pattern =
  '{ ($.errorCode = "ConsoleLogin") || ($.additionalEventData.MFAUsed != "Yes")  }'
const Aws_NIST_800_53_710_Filter_Pattern =
  '{ ($.errorCode =  "UnauthorizedOperation") || ($.errorCode = "AccessDenied") }'
const Aws_NIST_800_53_711_Filter_Pattern =
  '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'
const Aws_NIST_800_53_712_Filter_Pattern =
  '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'
const Aws_NIST_800_53_713_Filter_Pattern =
  '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }'
const Aws_NIST_800_53_714_Filter_Pattern =
  '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }'

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

export interface Cloudwatch {
  metric: string
}

export interface QueryawsAccount {
  id: string
  cloudtrail: QueryawsCloudtrailEntity[]
}

export interface QueryawsCloudfront {
  id: string
  cloudwatches: Cloudwatch[]
}

export interface NIST7xQueryResponse {
  queryawsAccount: QueryawsAccount[]
  queryawsCloudfront?: QueryawsCloudfront[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'NIST',
    })
  })

  const get7xValidResponse = (
    metricFilterPattern: string
  ): NIST7xQueryResponse => ({
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

  describe('AWS NIST 7.1 Alarm for denied connections in CloudFront logs should be configured', () => {
    const getTestRuleFixture = (
      metric1: string,
      metric2: string
    ): NIST7xQueryResponse => {
      return {
        queryawsAccount: [],
        queryawsCloudfront: [
          {
            id: cuid(),
            cloudwatches: [
              {
                metric: metric1
              },
              {
                metric: metric2
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIST7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_71 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Cloudfront has a CloudWatch alarm to trigger on HTTP 4xx and 5xx error codes', async () => {
      const data: NIST7xQueryResponse = getTestRuleFixture('4xxErrorRate','5xxErrorRate')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when Cloudfront has a only CloudWatch alarm to trigger on HTTP 4xx error codes', async () => {
      const data: NIST7xQueryResponse = getTestRuleFixture('4xxErrorRate','test')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when Cloudfront has a only CloudWatch alarm to trigger on HTTP 5xx error codes', async () => {
      const data: NIST7xQueryResponse = getTestRuleFixture('5xxErrorRate','test')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when Cloudfront has a not a CloudWatch alarm to trigger on HTTP 4xx and 5xx error codes', async () => {
      const data: NIST7xQueryResponse = getTestRuleFixture('','test')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 7.2 CloudWatch log metric filter and alarm for AWS Organizations changes should be configured for the master account', () => {
    const testRule = async (
      data: NIST7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_72 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for AWS Organizations changes', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_72_Filter_Pattern)
      await testRule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_72_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_72_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_72_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get7xValidResponse('dummy metric filter value')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_72_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 7.3 CloudWatch log metric filter and alarm for changes to VPC NACLs should be configured', () => {
    const testRule = async (
      data: NIST7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_73 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_73_Filter_Pattern)
      await testRule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_73_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_73_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_73_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get7xValidResponse('dummy metric filter value')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_73_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 7.4 CloudWatch log metric filter and alarm for changes to VPC network gateways should be configured', () => {
    const testRule = async (
      data: NIST7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_74 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_74_Filter_Pattern)
      await testRule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_74_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_74_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_74_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get7xValidResponse('dummy metric filter value')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_74_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 7.5 CloudWatch log metric filter and alarm for CloudTrail configuration changes should be configured', () => {
    const testRule = async (
      data: NIST7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_75 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_75_Filter_Pattern)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when isLogging is false', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_75_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_75_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_75_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern just contains one condition', async () => {
      const data = get7xValidResponse('{ ($.eventName = CreateTrail) }')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_75_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 7.7 CloudWatch log metric filter and alarm for IAM policy changes should be configured', () => {
    const testRule = async (
      data: NIST7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_77 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_77_Filter_Pattern)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when isLogging is false', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_77_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_77_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_77_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern just contains one condition', async () => {
      const data = get7xValidResponse('{ ($.eventName = DeleteGroupPolicy) }')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_77_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 7.8 CloudWatch log metric filter and alarm for Management Console authentication failures should be configured', () => {
    const testRule = async (
      data: NIST7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_78 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_78_Filter_Pattern)
      await testRule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_78_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_78_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_78_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get7xValidResponse('dummy metric filter value')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_78_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 7.9 CloudWatch log metric filter and alarm for Management Console sign-in without MFA should be configured', () => {
    const testRule = async (
      data: NIST7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_79 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_79_Filter_Pattern)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when isLogging is false', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_79_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_79_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_79_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern just contains one error code', async () => {
      const data = get7xValidResponse('{ ($.errorCode = "ConsoleLogin") }')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_79_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 7.10 CloudWatch log metric filter and alarm for unauthorized API calls should be configured', () => {
    const testRule = async (
      data: NIST7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_710 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_710_Filter_Pattern)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when isLogging is false', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_710_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_710_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_710_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern just contains one error code', async () => {
      const data = get7xValidResponse(
        '{ ($.errorCode =  "UnauthorizedOperation") }'
      )
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_710_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 7.11 CloudWatch log metric filter and alarm for usage of root account should be configured', () => {
    const testRule = async (
      data: NIST7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_711 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_711_Filter_Pattern)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when isLogging is false', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_711_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_711_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_711_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern just contains one condition', async () => {
      const data = get7xValidResponse(
        '{ $.userIdentity.type = "Root" || $.userIdentity.invokedBy NOT EXISTS }'
      )
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_711_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 7.12 CloudWatch log metric filter and alarm for VPC changes should be configured', () => {
    const testRule = async (
      data: NIST7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_712 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_712_Filter_Pattern)
      await testRule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_712_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_712_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_712_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get7xValidResponse('dummy metric filter value')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_712_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 7.13 Ensure a log metric filter and alarm exist for route table changes (Scored)', () => {
    const testRule = async (
      data: NIST7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_713 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_713_Filter_Pattern)
      await testRule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_713_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_713_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_713_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get7xValidResponse('dummy metric filter value')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_713_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 7.14 CloudWatch log metric filter and alarm for VPC security group changes should be configured', () => {
    const testRule = async (
      data: NIST7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_714 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_714_Filter_Pattern)
      await testRule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_714_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_714_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_714_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get7xValidResponse('dummy metric filter value')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get7xValidResponse(Aws_NIST_800_53_714_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })
})
