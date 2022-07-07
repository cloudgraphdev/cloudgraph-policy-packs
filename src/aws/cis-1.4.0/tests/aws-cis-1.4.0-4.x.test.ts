import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_CIS_140_41 from '../rules/aws-cis-1.4.0-4.1'
import Aws_CIS_140_42 from '../rules/aws-cis-1.4.0-4.2'
import Aws_CIS_140_43 from '../rules/aws-cis-1.4.0-4.3'
import Aws_CIS_140_44 from '../rules/aws-cis-1.4.0-4.4'
import Aws_CIS_140_45 from '../rules/aws-cis-1.4.0-4.5'
import Aws_CIS_140_46 from '../rules/aws-cis-1.4.0-4.6'
import Aws_CIS_140_47 from '../rules/aws-cis-1.4.0-4.7'
import Aws_CIS_140_48 from '../rules/aws-cis-1.4.0-4.8'
import Aws_CIS_140_49 from '../rules/aws-cis-1.4.0-4.9'
import Aws_CIS_140_410 from '../rules/aws-cis-1.4.0-4.10'
import Aws_CIS_140_411 from '../rules/aws-cis-1.4.0-4.11'
import Aws_CIS_140_412 from '../rules/aws-cis-1.4.0-4.12'
import Aws_CIS_140_413 from '../rules/aws-cis-1.4.0-4.13'
import Aws_CIS_140_414 from '../rules/aws-cis-1.4.0-4.14'
import Aws_CIS_140_415 from '../rules/aws-cis-1.4.0-4.15'
import { initRuleEngine } from '../../../utils/test'

const Aws_CIS_140_41_Filter_Pattern =
  '{ ($.errorCode =  "UnauthorizedOperation") || ($.errorCode = "AccessDenied") }'
const Aws_CIS_140_42_Filter_Pattern =
  '{ ($.errorCode = "ConsoleLogin") || ($.additionalEventData.MFAUsed != "Yes")  }'
const Aws_CIS_140_43_Filter_Pattern =
  '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'
const Aws_CIS_140_44_Filter_Pattern =
  '{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy)}'
const Aws_CIS_140_45_Filter_Pattern =
  '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }'
const Aws_CIS_140_46_Filter_Pattern =
  '{ ($.eventName = ConsoleLogin1) && ($.errorMessage = "Failed authentication") }'
const Aws_CIS_140_47_Filter_Pattern =
  '{ ($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion)) }'
const Aws_CIS_140_48_Filter_Pattern =
  '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }'
const Aws_CIS_140_49_Filter_Pattern =
  '{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel) ||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }'
const Aws_CIS_140_410_Filter_Pattern =
  '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }'
const Aws_CIS_140_411_Filter_Pattern =
  '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }'
const Aws_CIS_140_412_Filter_Pattern =
  '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'
const Aws_CIS_140_413_Filter_Pattern =
  '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }'
const Aws_CIS_140_414_Filter_Pattern =
  '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'
const Aws_CIS_140_415_Filter_Pattern =
  '{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy") || ($.eventName = "UpdateOrganizationalUnit")) }'

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

describe('CIS Amazon Web Services Foundations: 1.4.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'CIS')
  })

  const get4xValidResponse = (metricFilterPattern: string): QueryResponse => ({
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

  describe('AWS CIS 4.1 Ensure a log metric filter and alarm exist for unauthorized API calls', () => {
    const testRule = async (
      data: QueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_41 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get4xValidResponse(Aws_CIS_140_41_Filter_Pattern)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when isLogging is false', async () => {
      const data = get4xValidResponse(Aws_CIS_140_41_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get4xValidResponse(Aws_CIS_140_41_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get4xValidResponse(Aws_CIS_140_41_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern just contains one error code', async () => {
      const data = get4xValidResponse(
        '{ ($.errorCode =  "UnauthorizedOperation") }'
      )
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get4xValidResponse(Aws_CIS_140_41_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 4.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)', () => {
    const testRule = async (
      data: QueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_42 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get4xValidResponse(Aws_CIS_140_42_Filter_Pattern)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when isLogging is false', async () => {
      const data = get4xValidResponse(Aws_CIS_140_42_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get4xValidResponse(Aws_CIS_140_42_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get4xValidResponse(Aws_CIS_140_42_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern just contains one error code', async () => {
      const data = get4xValidResponse('{ ($.errorCode = "ConsoleLogin") }')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get4xValidResponse(Aws_CIS_140_42_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe("AWS CIS 4.3  Ensure a log metric filter and alarm exist for usage of 'root' account", () => {
    const testRule = async (
      data: QueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_43 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get4xValidResponse(Aws_CIS_140_43_Filter_Pattern)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when isLogging is false', async () => {
      const data = get4xValidResponse(Aws_CIS_140_43_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get4xValidResponse(Aws_CIS_140_43_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get4xValidResponse(Aws_CIS_140_43_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern just contains one condition', async () => {
      const data = get4xValidResponse(
        '{ $.userIdentity.type = "Root" || $.userIdentity.invokedBy NOT EXISTS }'
      )
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get4xValidResponse(Aws_CIS_140_43_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 4.4 Ensure a log metric filter and alarm exist for IAM policy changes', () => {
    const testRule = async (
      data: QueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_44 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get4xValidResponse(Aws_CIS_140_44_Filter_Pattern)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when isLogging is false', async () => {
      const data = get4xValidResponse(Aws_CIS_140_44_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get4xValidResponse(Aws_CIS_140_44_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get4xValidResponse(Aws_CIS_140_44_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern just contains one condition', async () => {
      const data = get4xValidResponse('{ ($.eventName = DeleteGroupPolicy) }')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get4xValidResponse(Aws_CIS_140_44_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 4.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes', () => {
    const testRule = async (
      data: QueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_45 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get4xValidResponse(Aws_CIS_140_45_Filter_Pattern)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when isLogging is false', async () => {
      const data = get4xValidResponse(Aws_CIS_140_45_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get4xValidResponse(Aws_CIS_140_45_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get4xValidResponse(Aws_CIS_140_45_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern just contains one condition', async () => {
      const data = get4xValidResponse('{ ($.eventName = CreateTrail) }')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get4xValidResponse(Aws_CIS_140_45_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 4.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures', () => {
    const testRule = async (
      data: QueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_46 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get4xValidResponse(Aws_CIS_140_46_Filter_Pattern)
      await testRule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get4xValidResponse(Aws_CIS_140_46_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get4xValidResponse(Aws_CIS_140_46_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get4xValidResponse(Aws_CIS_140_46_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get4xValidResponse('dummy metric filter value')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get4xValidResponse(Aws_CIS_140_46_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 4.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs',
    () => {
      const testRule = async (
        data: QueryResponse,
        expectedResult: Result
      ): Promise<void> => {
        // Act
        const [processedRule] = await rulesEngine.processRule(
          Aws_CIS_140_47 as Rule,
          { ...data }
        )

        // Asserts
        expect(processedRule.result).toBe(expectedResult)
      }

      test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
        const data = get4xValidResponse(Aws_CIS_140_47_Filter_Pattern)
        await testRule(data, Result.PASS)
      })
      test('Security Issue when isLogging is false', async () => {
        const data = get4xValidResponse(Aws_CIS_140_47_Filter_Pattern)
        data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
        await testRule(data, Result.FAIL)
      })
      test('Security Issue when eventSelectors readWriteType is not All', async () => {
        const data = get4xValidResponse(Aws_CIS_140_47_Filter_Pattern)
        data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
          'dummy'
        await testRule(data, Result.FAIL)
      })
      test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
        const data = get4xValidResponse(Aws_CIS_140_47_Filter_Pattern)
        data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
          false
        await testRule(data, Result.FAIL)
      })
      test('Security Issue when metricFilters filterPattern is not found', async () => {
        const data = get4xValidResponse('dummy metric filter value')
        await testRule(data, Result.FAIL)
      })
      test('Security Issue when cloudwatch sns suscription is not found', async () => {
        const data = get4xValidResponse(Aws_CIS_140_47_Filter_Pattern)
        data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
          []
        await testRule(data, Result.FAIL)
      })
    }
  )

  describe('AWS CIS 4.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes', () => {
    const testRule = async (
      data: QueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_48 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get4xValidResponse(Aws_CIS_140_48_Filter_Pattern)
      await testRule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get4xValidResponse(Aws_CIS_140_48_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get4xValidResponse(Aws_CIS_140_48_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get4xValidResponse(Aws_CIS_140_48_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get4xValidResponse('dummy metric filter value')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get4xValidResponse(Aws_CIS_140_48_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 4.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes', () => {
    const test39Rule = async (
      data: QueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_49 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get4xValidResponse(Aws_CIS_140_49_Filter_Pattern)
      await test39Rule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get4xValidResponse(Aws_CIS_140_49_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await test39Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get4xValidResponse(Aws_CIS_140_49_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await test39Rule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get4xValidResponse(Aws_CIS_140_49_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await test39Rule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get4xValidResponse('dummy metric filter value')
      await test39Rule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get4xValidResponse(Aws_CIS_140_49_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await test39Rule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 4.10 Ensure a log metric filter and alarm exist for security group changes', () => {
    const testRule = async (
      data: QueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_410 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get4xValidResponse(Aws_CIS_140_410_Filter_Pattern)
      await testRule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get4xValidResponse(Aws_CIS_140_410_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get4xValidResponse(Aws_CIS_140_410_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get4xValidResponse(Aws_CIS_140_410_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get4xValidResponse('dummy metric filter value')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get4xValidResponse(Aws_CIS_140_410_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 4.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)', () => {
    const testRule = async (
      data: QueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_411 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get4xValidResponse(Aws_CIS_140_411_Filter_Pattern)
      await testRule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get4xValidResponse(Aws_CIS_140_411_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get4xValidResponse(Aws_CIS_140_411_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get4xValidResponse(Aws_CIS_140_411_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get4xValidResponse('dummy metric filter value')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get4xValidResponse(Aws_CIS_140_411_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 4.12 Ensure a log metric filter and alarm exist for changes to network gateways', () => {
    const testRule = async (
      data: QueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_412 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get4xValidResponse(Aws_CIS_140_412_Filter_Pattern)
      await testRule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get4xValidResponse(Aws_CIS_140_412_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get4xValidResponse(Aws_CIS_140_412_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get4xValidResponse(Aws_CIS_140_412_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get4xValidResponse('dummy metric filter value')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get4xValidResponse(Aws_CIS_140_412_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 4.13 Ensure a log metric filter and alarm exist for route table changes', () => {
    const testRule = async (
      data: QueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_413 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get4xValidResponse(Aws_CIS_140_413_Filter_Pattern)
      await testRule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get4xValidResponse(Aws_CIS_140_413_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get4xValidResponse(Aws_CIS_140_413_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get4xValidResponse(Aws_CIS_140_413_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get4xValidResponse('dummy metric filter value')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get4xValidResponse(Aws_CIS_140_413_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 4.14 Ensure a log metric filter and alarm exist for VPC changes', () => {
    const testRule = async (
      data: QueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_414 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for security group changes', async () => {
      const data = get4xValidResponse(Aws_CIS_140_414_Filter_Pattern)
      await testRule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get4xValidResponse(Aws_CIS_140_414_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get4xValidResponse(Aws_CIS_140_414_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get4xValidResponse(Aws_CIS_140_414_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get4xValidResponse('dummy metric filter value')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get4xValidResponse(Aws_CIS_140_414_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 4.15 Ensure a log metric filter and alarm exists for AWS Organizations changes', () => {
    const testRule = async (
      data: QueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_415 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are metric filters and alarms for AWS Organizations changes', async () => {
      const data = get4xValidResponse(Aws_CIS_140_415_Filter_Pattern)
      await testRule(data, Result.PASS)
    })
    test('Security Issue when isLogging is false', async () => {
      const data = get4xValidResponse(Aws_CIS_140_415_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].status.isLogging = false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors readWriteType is not All', async () => {
      const data = get4xValidResponse(Aws_CIS_140_415_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].readWriteType =
        'dummy'
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when eventSelectors includeManagementEvents is not true', async () => {
      const data = get4xValidResponse(Aws_CIS_140_415_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].eventSelectors[0].includeManagementEvents =
        false
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when metricFilters filterPattern is not found', async () => {
      const data = get4xValidResponse('dummy metric filter value')
      await testRule(data, Result.FAIL)
    })
    test('Security Issue when cloudwatch sns suscription is not found', async () => {
      const data = get4xValidResponse(Aws_CIS_140_415_Filter_Pattern)
      data.queryawsAccount[0].cloudtrail[0].cloudwatchLog[0].cloudwatch[1].sns[0].subscriptions =
        []
      await testRule(data, Result.FAIL)
    })
  })
})
