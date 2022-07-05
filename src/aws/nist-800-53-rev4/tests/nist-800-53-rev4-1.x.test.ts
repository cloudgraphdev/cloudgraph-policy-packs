import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_NIST_800_53_11 from '../rules/aws-nist-800-53-rev4-1.1'
import Aws_NIST_800_53_12 from '../rules/aws-nist-800-53-rev4-1.2'
import Aws_NIST_800_53_13 from '../rules/aws-nist-800-53-rev4-1.3'

export interface Principal {
  key?: string
  value: string[]
}

export interface Statement {
  principal?: Principal[]
  effect?: string
  action?: string[]
}

export interface AssumeRolePolicy {
  statement: Statement[]
}

export interface PolicyContent {
  statement: Statement[]
}

export interface IamAttachedPolicy {
  policyContent: PolicyContent
}

export interface InstanceProfile {
  arn: string
}

export interface QueryawsIamRole {
  id: string
  assumeRolePolicy?: AssumeRolePolicy
  iamAttachedPolicies?: IamAttachedPolicy[]
  iamInstanceProfiles?: InstanceProfile[] | undefined
}

export interface Policy {
  statement: Statement[]
}

export interface S3 {
  policy?: PolicyContent
}

export interface QueryawsCloudtrail {
  id: string
  s3?: S3[]
}

export interface NIS1xQueryResponse {
  queryawsIamRole?: QueryawsIamRole[]
  queryawsCloudtrail?: QueryawsCloudtrail[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'NIST',
    })
  })

  describe('AWS NIST 1.1 IAM role trust policies should not allow all principals to assume the role', () => {
    const getTestRuleFixture = (principalRole: string): NIS1xQueryResponse => {
      return {
        queryawsIamRole: [
          {
            id: cuid(),
            assumeRolePolicy: {
              statement: [
                {
                  principal: [
                    {
                      value: [principalRole],
                    },
                  ],
                },
              ],
            },
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_11 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when IAM role trust policies not allow all principals to assume the role', async () => {
      const data: NIS1xQueryResponse = getTestRuleFixture(
        'arn:aws:iam::204762158545:root'
      )
      await testRule(data, Result.PASS)
    })

    test('Security Issue when IAM role trust policies allow all principals to assume the role', async () => {
      const data: NIS1xQueryResponse = getTestRuleFixture('*')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 1.2 IAM roles attached to instance profiles should not allow broad list actions on S3 buckets', () => {
    const getTestRuleFixture = (
      effect: string,
      action: string[]
    ): NIS1xQueryResponse => {
      return {
        queryawsIamRole: [
          {
            id: cuid(),
            iamInstanceProfiles: [
              {
                arn: 'arn:aws:iam::632941798677:instance-profile/autocloud-sandbox-ec2-assume-test',
              },
            ],
            iamAttachedPolicies: [
              {
                policyContent: {
                  statement: [
                    {
                      effect,
                      action,
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_12 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when IAM roles attached to instance profiles not allow broad list actions on S3 buckets', async () => {
      const data: NIS1xQueryResponse = getTestRuleFixture('Allow', ['s3:Get*'])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when IAM roles attached to instance profiles allow broad list actions on S3 buckets', async () => {
      const data: NIS1xQueryResponse = getTestRuleFixture('Allow', [
        'ListBuckets',
        'S3:List*',
        'S3:*',
      ])
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when IAM roles attached to instance profiles allow ListBuckets action on S3 buckets', async () => {
      const data: NIS1xQueryResponse = getTestRuleFixture('Allow', [
        'ListBuckets',
      ])
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when IAM roles attached to instance profiles allow S3:List* action on S3 buckets', async () => {
      const data: NIS1xQueryResponse = getTestRuleFixture('Allow', ['S3:List*'])
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when IAM roles attached to instance profiles allow S3:* action on S3 buckets', async () => {
      const data: NIS1xQueryResponse = getTestRuleFixture('Allow', ['S3:*'])
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 1.3 S3 bucket ACLs should not have public access on S3 buckets that store CloudTrail log files', () => {
    const getTestRuleFixture = (
      effect: string,
      key: string,
      value: string
    ): NIS1xQueryResponse => {
      return {
        queryawsCloudtrail: [
          {
            id: cuid(),
            s3: [
              {
                policy: {
                  statement: [
                    {
                      effect,
                      principal: [
                        {
                          key,
                          value: [value],
                        },
                      ],
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_13 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when S3 bucket ACLs not have public access on S3 buckets that store CloudTrail log files', async () => {
      const data: NIS1xQueryResponse = getTestRuleFixture(
        'Allow',
        'Service',
        'cloudtrail.amazonaws.com'
      )
      await testRule(data, Result.PASS)
    })

    test('Security Issue when S3 bucket ACLs have a policy that contains a statement having an Effect set to Allow and a Principal set to "*"', async () => {
      const data: NIS1xQueryResponse = getTestRuleFixture('Allow', '', '*')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when S3 bucket ACLs have a policy that contains a statement having an Effect set to Allow and a Principal set to {"AWS" : "*"}', async () => {
      const data: NIS1xQueryResponse = getTestRuleFixture('Allow', 'AWS', '*')
      await testRule(data, Result.FAIL)
    })
  })
})
