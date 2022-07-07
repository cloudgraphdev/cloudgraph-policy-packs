import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_CIS_140_14 from '../rules/aws-cis-1.4.0-1.4'
import Aws_CIS_140_15 from '../rules/aws-cis-1.4.0-1.5'
import Aws_CIS_140_16 from '../rules/aws-cis-1.4.0-1.6'
import Aws_CIS_140_17 from '../rules/aws-cis-1.4.0-1.7'
import Aws_CIS_140_18 from '../rules/aws-cis-1.4.0-1.8'
import Aws_CIS_140_19 from '../rules/aws-cis-1.4.0-1.9'
import Aws_CIS_140_110 from '../rules/aws-cis-1.4.0-1.10'
import Aws_CIS_140_112 from '../rules/aws-cis-1.4.0-1.12'
import Aws_CIS_140_113 from '../rules/aws-cis-1.4.0-1.13'
import Aws_CIS_140_114 from '../rules/aws-cis-1.4.0-1.14'
import Aws_CIS_140_115 from '../rules/aws-cis-1.4.0-1.15'
import Aws_CIS_140_116 from '../rules/aws-cis-1.4.0-1.16'
import Aws_CIS_140_117 from '../rules/aws-cis-1.4.0-1.17'
import Aws_CIS_140_119 from '../rules/aws-cis-1.4.0-1.19'
import Aws_CIS_140_120 from '../rules/aws-cis-1.4.0-1.20'
import { initRuleEngine } from '../../../utils/test'

export interface VirtualMfaDevice {
  serialNumber: string
}

export interface AccessKeyData {
  lastUsedDate?: string
  status?: string
  lastRotated?: string
}

export interface IamAttachedPolicy {
  arn?: string
  name?: string
}

export interface Statement {
  effect?: string
  action?: string[]
  resource?: string[]
}

export interface AssumeRolePolicy {
  statement: Statement[]
}

export interface PolicyContent {
  statement: Statement[]
}
export interface QueryawsIamPolicy {
  id: string
  policyContent: PolicyContent
}

export interface QueryawsIamUser {
  id: string
  name?: string
  accessKeysActive?: boolean
  mfaActive?: boolean
  accountId?:string
  virtualMfaDevices?: VirtualMfaDevice[]
  passwordEnabled?: boolean
  passwordLastUsed?: string
  accessKeyData?: AccessKeyData[]
  iamAttachedPolicies?: IamAttachedPolicy[]
  inlinePolicies?: string[]
  
}

export interface QueryawsIamPasswordPolicy {
  id: string
  minimumPasswordLength?: number
  requireNumbers?: boolean
  passwordReusePrevention?: number
  requireLowercaseCharacters?: boolean
  requireSymbols?: boolean
  requireUppercaseCharacters?: boolean
  expirePasswords?: boolean
  maxPasswordAge?: number
}

export interface iamRole {
  arn: string
}

export interface iamGroup {
  arn: string
}

export interface IamUser {
  arn: string
}

export interface IamPolicy {
  name: string
  iamUsers: IamUser[]
  iamGroups: iamGroup[]
  iamRoles: iamRole[]
}

export interface IamAccessAnalyzer {
  status: string
  region: string
}

export interface QueryawsIamServerCertificate {
  id: string
  expiration: string
}

export interface QueryawsAccount {
  id: string
  regions?: string[]
  iamPolicies?: IamPolicy[]
  iamAccessAnalyzers?: IamAccessAnalyzer[]
}

export interface CIS1xQueryResponse {
  queryawsIamUser?: QueryawsIamUser[]
  queryawsIamPasswordPolicy?: QueryawsIamPasswordPolicy[]
  queryawsIamPolicy?: QueryawsIamPolicy[]
  queryawsAccount?: QueryawsAccount[]
  queryawsIamServerCertificate?: QueryawsIamServerCertificate[]
}

describe('CIS Amazon Web Services Foundations: 1.4.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'CIS')
  })

  describe('AWS CIS 1.4 Ensure no root user account access key exists', () => {
    const getTestRuleFixture = (
      accessKeysActive: boolean
    ): CIS1xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            accessKeysActive,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_14 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when a root account does not have any access key active', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when a root account has at least one access key active', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 1.5 Ensure MFA is enabled for the root user account', () => {
    const getTestRuleFixture = (
      mfaActive: boolean
    ): CIS1xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            mfaActive,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_15 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when a root account has a mfa device active', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when a root account has not a mfa device active', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 1.6 Ensure hardware MFA is enabled for the root user account', () => {
    const getTestRuleFixture = (
      mfaActive: boolean
    ): CIS1xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            mfaActive,
            accountId: '123456',
            virtualMfaDevices: [
              {
                serialNumber: 'arn:aws:iam::123456:mfa/some-account-mfa-device',
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_16 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when a root account has a mfa hardware device active', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when a root account has a mfa hardware device deactivate', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 1.6 Eliminate use of the root user for administrative and daily tasks', () => {
    const getTestRuleFixture = (
      mfaActive: boolean
    ): CIS1xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            mfaActive,
            accountId: '123456',
            virtualMfaDevices: [
              {
                serialNumber: 'arn:aws:iam::123456:mfa/some-account-mfa-device',
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_16 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when a root account has a mfa hardware device active', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when a root account has a mfa hardware device deactivate', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 1.7 Eliminate use of the root user for administrative and daily tasks', () => {
    const getTestRuleFixture = (
      passwordLastUsed: string,
      status: string,
      lastUsedDate: string
    ): CIS1xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            passwordEnabled: true,
            passwordLastUsed,
            accessKeysActive: true,
            accessKeyData: [
              {
                status,
                lastUsedDate,
              },
              {
                status: 'Active',
                lastUsedDate: '2022-01-01T17:20:19.000Z',
              }
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_17 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when when a root account does not uses his password in the last 90 days', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('2021-04-08T17:20:19.000Z', 'Active', '2021-10-08T17:20:19.000Z')
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when when a root account does not uses his password in the last 90 days and not have access Keys', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('2021-04-08T17:20:19.000Z', '', '')
      const user = data.queryawsIamUser?.[0] as QueryawsIamUser
      user.accessKeyData = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when a root account uses his password in the last 90 days', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(new Date().toISOString(), 'Active', '2021-10-08T17:20:19.000Z')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when a root account uses his access Keys in the last 90 days', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('2021-04-08T17:20:19.000Z', 'Active', new Date().toISOString())
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 1.8 Ensure IAM password policy requires minimum length of 14 or greater', () => {
    const getTestRuleFixture = (
      minimumPasswordLength: number
    ): CIS1xQueryResponse => {
      return {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            minimumPasswordLength,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_18 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when password policy minimum length is greater than or equal to 14', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(14)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when password policy minimum length is less than 14', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(13)
      await testRule(data, Result.FAIL)
    })

  })

  describe('AWS CIS 1.9 Ensure IAM password policy prevents password reuse', () => {
    const getTestRuleFixture = (
      passwordReusePrevention: number
    ): CIS1xQueryResponse => {
      return {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            passwordReusePrevention,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_19 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue if the number of previous passwords is more than 24', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(25)
      await testRule(data, Result.PASS)
    })

    test('Security Issue if the number of previous passwords is less than 24', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(23)
      await testRule(data, Result.FAIL)
    })

  })

  describe('AWS CIS 1.10 Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password', () => {
    const getTestRuleFixture = (
      passwordEnabled: boolean,
      mfaActive: boolean
    ): CIS1xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            passwordEnabled,
            mfaActive,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_110 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when a user has no active password', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(false, true)
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when a user has an active password with an mfa device register', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(true, true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when a user has an active password without an mfa device register', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(true, false)
      await testRule(data, Result.FAIL)
    })

  })

  describe('AWS CIS 1.12 Ensure credentials unused for 45 days or greater are disabled', () => {
    const getTestRuleFixture = (
      passwordLastUsed: string,
      lastUsedDate: string
    ): CIS1xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            passwordLastUsed,
            accessKeyData: [
              {
                lastUsedDate,
              }
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_112 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there are an access key unused for less than 90 days', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('', new Date().toISOString())
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when no password last used AND no access key data', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('', '')
      const queryawsIamUser = data.queryawsIamUser?.[0] as QueryawsIamUser
      queryawsIamUser.accessKeyData = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there are an access key unused for more than 90 days', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('', '2021-05-27T20:29:00.000Z')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there are a passwoord unused for more than 90 days', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('2021-05-27T20:29:00.000Z', '')
      const queryawsIamUser = data.queryawsIamUser?.[0] as QueryawsIamUser
      queryawsIamUser.accessKeyData = []
      await testRule(data, Result.FAIL)
    })

  })

  describe('AWS CIS 1.13 Ensure there is only one active access key available for any single IAM user', () => {
    const getTestRuleFixture = (
      status: string
    ): CIS1xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            accessKeyData: [
              {
                status,
              },
              {
                status: 'Active',
              }
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_113 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there is only one active access key available for any single IAM user', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('Inactive')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there are more than one active access key available for any single IAM user', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('Active')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 1.14 Ensure access keys are rotated every 90 days or less', () => {
    const getTestRuleFixture = (
      status: string,
      lastRotated: string
    ): CIS1xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            accessKeyData: [
              {
                status,
                lastRotated,
              },
              {
                status: 'Active',
                lastRotated: '2021-08-27T15:00:44.000Z',
              }
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_114 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when users have an active access key created for less than 90 days', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('Active', new Date().toISOString())
      await testRule(data, Result.PASS)
    })

    test('Security Issue when users have an active access key created for more than 90 days', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('Active', '2021-09-23T15:56:01.000Z')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 1.15 Ensure IAM Users Receive Permissions Only Through Groups', () => {
    const getTestRuleFixture = (
      iamAttachedPolicies: IamAttachedPolicy[],
      inlinePolicies: string[]
    ): CIS1xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            iamAttachedPolicies,
            inlinePolicies,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_115 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when users does not have attached policies directly', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture([],[])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when users have attached policies directly', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture([{ arn: cuid() }], ['inline_test'])
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 1.16 Ensure IAM policies that allow full "*:*" administrative privileges are not attached', () => {
    const getTestRuleFixture = (
      effect: string,
      action: string[],
      resource: string[]
    ): CIS1xQueryResponse => {
      return {
        queryawsIamPolicy: [
          {
            id: cuid(),
            policyContent: {
              statement: [
                {
                  effect,
                  action,
                  resource
                }
              ]
            }
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_116 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when IAM policies not allow full "*:*" administrative privileges', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('Allow',  [
        'secretsmanager:DeleteSecret',
        'secretsmanager:GetSecretValue',
        'secretsmanager:UpdateSecret',
      ], ['arn:aws:secretsmanager:*:*:secret:A4B*'])
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when IAM policies that have a statement with "Effect": "Allow" with "Action": "*" over restricted "Resource"', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('Allow', ['*'], ['arn:aws:secretsmanager:*:*:secret:A4B*'])
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when IAM policies that have a statement with "Effect": "Allow" with restricted "Action" over "Resource": "*"', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('Allow',  [
        'secretsmanager:DeleteSecret',
        'secretsmanager:GetSecretValue',
        'secretsmanager:UpdateSecret',
      ], ['*'])
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when IAM policies that allow full "*:*" administrative privileges', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('Allow',  ['*'], ['*'])
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 1.17 Ensure a support role has been created to manage incidents with AWS Support', () => {
    const getTestRuleFixture = (
      name: string,
      iamUsers: IamUser[],
      iamGroups: iamGroup[],
      iamRoles: iamRole[]
    ): CIS1xQueryResponse => {
      return {
        queryawsAccount: [
          {
            id: cuid(),
            iamPolicies: [
              {
                name,
                iamUsers,
                iamGroups,
                iamRoles
              }
            ]
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_117 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when AWSSupportAccess is attached to IAM users', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('AWSSupportAccess', [{arn: 'arn:aws:iam::632941798677:user/test'}], [], [])
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when AWSSupportAccess is attached to any IAM groups', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('AWSSupportAccess', [], [{arn: 'arn:aws:iam::632941798677:user/test'}], [])
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when AWSSupportAccess is attached to any IAM roles', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('AWSSupportAccess', [], [], [{arn: 'arn:aws:iam::632941798677:user/test'}])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when AWSSupportAccess is not attached to any IAM user, group or role', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('AWSSupportAccess', [], [], [])
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when AWSSupportAccess does not exists', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('PolicyTest', [], [], [{arn: 'arn:aws:iam::632941798677:user/test'}])
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there are no IAM policies', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('', [], [], [])
      const account = data.queryawsAccount?.[0] as QueryawsAccount
      account.iamPolicies = []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 1.19 Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed', () => {
    const getTestRuleFixture = (
      expiration: string,
    ): CIS1xQueryResponse => {
      return {
        queryawsIamServerCertificate: [
          {
            id: cuid(),
            expiration
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_119 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when thre not are expired SSL/TLS certificates', async () => {
      const day = 1000 * 60 * 60 * 24
      const data: CIS1xQueryResponse = getTestRuleFixture(new Date(Date.now() + 30 * day).toISOString())
      await testRule(data, Result.PASS)
    })

    test('Security Issue when thre are expired SSL/TLS certificates', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture(new Date().toISOString())
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 1.20 Ensure that IAM Access analyzer is enabled for all regions', () => {
    const getTestRuleFixture = (
      statusRegion1: string,
      statusRegion2: string,
    ): CIS1xQueryResponse => {
      return {
        queryawsAccount: [
          {
            id: cuid(),
            regions: ['us-east-1', 'us-east-2'],
            iamAccessAnalyzers: [
              {
                region: 'us-east-1',
                status: statusRegion1,
              },
              {
                region: 'us-east-2',
                status: statusRegion2,
              }
            ]
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_140_120 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when at least one analyzer is enabled for all regions', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('ACTIVE','ACTIVE')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there are an analyzer disabled for some region', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('ACTIVE', 'INACTIVE')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when no analyzer enabled for any region', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('INACTIVE', 'INACTIVE')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when when no analyzer is configured', async () => {
      const data: CIS1xQueryResponse = getTestRuleFixture('','')
      const account = data.queryawsAccount?.[0] as QueryawsAccount
      account.iamAccessAnalyzers = []
      await testRule(data, Result.FAIL)
    })
  })
})

