import cuid from 'cuid'
import CloudGraph, { Rule, Engine } from '@cloudgraph/sdk'

import Aws_CIS_120_11 from '../rules/aws-cis-1.2.0-1.1'
import Aws_CIS_120_12 from '../rules/aws-cis-1.2.0-1.2'
import Aws_CIS_120_13 from '../rules/aws-cis-1.2.0-1.3'
import Aws_CIS_120_14 from '../rules/aws-cis-1.2.0-1.4'
import Aws_CIS_120_15 from '../rules/aws-cis-1.2.0-1.5'
import Aws_CIS_120_16 from '../rules/aws-cis-1.2.0-1.6'
import Aws_CIS_120_17 from '../rules/aws-cis-1.2.0-1.7'
import Aws_CIS_120_18 from '../rules/aws-cis-1.2.0-1.8'
import Aws_CIS_120_19 from '../rules/aws-cis-1.2.0-1.9'
import Aws_CIS_120_110 from '../rules/aws-cis-1.2.0-1.10'
import Aws_CIS_120_111 from '../rules/aws-cis-1.2.0-1.11'
import Aws_CIS_120_112 from '../rules/aws-cis-1.2.0-1.12'
import Aws_CIS_120_113 from '../rules/aws-cis-1.2.0-1.13'
import Aws_CIS_120_114 from '../rules/aws-cis-1.2.0-1.14'
import Aws_CIS_120_116 from '../rules/aws-cis-1.2.0-1.16'

describe('CIS Amazon Web Services Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine()
  })
  describe("AWS CIS 1.1 Avoid the use of 'root' account. Show used in last 30 days (Scored)", () => {
    test('Should fail when a root account uses his password in the last 30 days', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            passwordEnabled: true,
            passwordLastUsed: '2021-04-08T17:20:19.000Z',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_11 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should pass when a root account does not uses his password in the last 30 days', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            passwordEnabled: true,
            passwordLastUsed: new Date().toISOString(),
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_11 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })

  describe('AWS CIS 1.2 Ensure MFA is enabled for all IAM users that have a console password (Scored)', () => {
    test('Should fail when a user has an active password without an mfa device register', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            passwordEnabled: true,
            mfaActive: false,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_12 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should pass when a user has an active password with an mfa device register', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            passwordEnabled: true,
            mfaActive: true,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_12 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })

  describe('AWS CIS 1.3 Ensure credentials unused for 90 days or greater are disabled', () => {
    test('Should fail given an access key unused for more than 90 days', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            passwordLastUsed: '',
            accessKeyData: [
              {
                lastUsedDate: '2021-05-27T20:29:00.000Z',
              },
              {
                lastUsedDate: '2021-05-12T15:09:00.000Z',
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_13 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should fail given a passwoord unused for more than 90 days', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            passwordLastUsed: '2021-05-27T20:29:00.000Z',
            accessKeyData: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_13 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should pass given an access key unused for less than 90 days', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            passwordLastUsed: '',
            accessKeyData: [
              {
                lastUsedDate: new Date().toISOString(),
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_13 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })

  describe('AWS CIS 1.4 Ensure access keys are rotated every 90 days or less', () => {
    test('Should fail given a user with an active access key created for more than 90 days', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            accessKeyData: [
              {
                status: 'Active',
                lastRotated: '2021-05-26T19:43:52.000Z',
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_14 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should pass given a user with an active access key created for less than 90 days', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            accessKeyData: [
              {
                status: 'Active',
                lastRotated: new Date().toISOString(),
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_14 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })

  describe('AWS CIS 1.5  Ensure IAM password policy requires at least one uppercase letter', () => {
    test('Should fail given a password policy without required uppercase letter', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireUppercaseCharacters: false,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_15 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should pass given a password policy that must have at least one uppercase letter', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireUppercaseCharacters: true,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_15 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })

  describe('AWS CIS 1.6  Ensure IAM password policy requires at least one lowercase letter', () => {
    test('Should fail given a password policy without required lowercase letter', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireLowercaseCharacters: false,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_16 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should pass given a password policy that must have at least one lowercase letter', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireLowercaseCharacters: true,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_16 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })

  describe('AWS CIS 1.7  Ensure IAM password policy requires at least one symbol', () => {
    test('Should fail given a password policy without required symbols', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireSymbols: false,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_17 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should pass given a password policy that must have at least one symbols', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireSymbols: true,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_17 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })

  describe('AWS CIS 1.8  Ensure IAM password policy requires at least one number', () => {
    test('Should fail given a password policy without required numbers', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireNumbers: false,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_18 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should pass given a password policy that must have at least one number', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireNumbers: true,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_18 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })

  describe('AWS CIS 1.9 Ensure IAM password policy requires minimum length of 14 or greater', () => {
    test('Should fail given a password policy length of 13', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            minimumPasswordLength: 13,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_19 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should pass given a password policy length of 14', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            minimumPasswordLength: 14,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_19 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })

  describe('AWS CIS 1.10 Ensure IAM password policy prevents password reuse', () => {
    test('Should fail if the number of previous passwords is less than 24', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            __typename: 'awsIamPasswordPolicy',
            passwordReusePrevention: 6,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_110 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should pass if the number of previous passwords is more than 24', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            __typename: 'awsIamPasswordPolicy',
            passwordReusePrevention: 25,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_110 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })

  describe('AWS CIS 1.11 Ensure IAM password policy expires passwords within 90 days or less', () => {
    test('Should fail given a password that expires after 90 days or more', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            __typename: 'awsIamPasswordPolicy',
            maxPasswordAge: 180,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_111 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should pass given a password that expires within 90 days or less', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            __typename: 'awsIamPasswordPolicy',
            maxPasswordAge: 30,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_111 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })

  describe('AWS CIS 1.12  Ensure no root account access key exists (Scored)', () => {
    test('Should fail when a root account has at least one access key active', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            accessKeysActive: true,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_112 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should pass when a root account does not have any access key active', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            accessKeysActive: false,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_112 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })

  describe("AWS CIS 1.13 Ensure MFA is enabled for the 'root' account", () => {
    test('Should fail when a root account has not a mfa device active', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            mfaActive: false,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_113 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should pass when a root account has a mfa device active', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            mfaActive: true,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_113 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })

  describe("AWS CIS 1.14 Ensure hardware MFA is enabled for the 'root' account (Scored)", () => {
    test('Should fail when a root account has not a mfa hardware device active', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            mfaActive: false,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_114 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should pass when a root account has a mfa hardware device active', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            mfaActive: true,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_114 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })

  describe('AWS CIS 1.16 Ensure IAM policies are attached only to groups or roles (Scored)', () => {
    test('Should fail when a user has attached policies directly', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            iamAttachedPolicies: [{ arn: cuid() }],
            inlinePolicies: ['inline_test'],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_116 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(CloudGraph.Result.FAIL)
    })

    test('Should pass when a user does not have attached policies directly', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            iamAttachedPolicies: [],
            inlinePolicies: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_116 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(CloudGraph.Result.PASS)
    })
  })
})
