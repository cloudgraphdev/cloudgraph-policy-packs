import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_IAM_1 from '../rules/pci-dss-3.2.1-iam-check-1'
import Aws_PCI_DSS_321_IAM_2 from '../rules/pci-dss-3.2.1-iam-check-2'
import Aws_PCI_DSS_321_IAM_3 from '../rules/pci-dss-3.2.1-iam-check-3'
import Aws_PCI_DSS_321_IAM_4 from '../rules/pci-dss-3.2.1-iam-check-4'
import Aws_PCI_DSS_321_IAM_5 from '../rules/pci-dss-3.2.1-iam-check-5'
import Aws_PCI_DSS_321_IAM_6 from '../rules/pci-dss-3.2.1-iam-check-6'
import Aws_PCI_DSS_321_IAM_7 from '../rules/pci-dss-3.2.1-iam-check-7'
import Aws_PCI_DSS_321_IAM_8 from '../rules/pci-dss-3.2.1-iam-check-8'
import { initRuleEngine } from '../../../utils/test'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'PCI')
  })

  describe('IAM Check 1: IAM root user access key should not exist', () => {
    test('Should fail when root account has at least one access key active', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            accessKeysActive: true,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when a root account does not have any access key active', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            accessKeysActive: false,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('IAM Check 2: IAM root user access key should not exist', () => {
    test('Should fail when a user has attached policies directly', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            iamAttachedPolicies: [{ id: cuid() }],
            inlinePolicies: ['inline_test'],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
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
        Aws_PCI_DSS_321_IAM_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('IAM Check 3: IAM policies should not allow full "*" administrative privileges', () => {
    test('Should pass for IAM policies that not allow full "*:*" administrative privileges', async () => {
      const data = {
        queryawsIamPolicy: [
          {
            id: cuid(),
            name: 'AdministratorAccess-Amplify',
            policyContent: {
              statement: [
                {
                  effect: 'Allow',
                  action: [
                    'secretsmanager:DeleteSecret',
                    'secretsmanager:GetSecretValue',
                    'secretsmanager:UpdateSecret',
                  ],
                  resource: ['arn:aws:secretsmanager:*:*:secret:A4B*'],
                },
              ],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_3 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass for IAM policies that have a statement with "Effect": "Allow" with "Action": "*" over restricted "Resource"', async () => {
      const data = {
        queryawsIamPolicy: [
          {
            id: cuid(),
            name: 'AdministratorAccess-Amplify',
            policyContent: {
              statement: [
                {
                  effect: 'Allow',
                  action: ['*'],
                  resource: ['arn:aws:secretsmanager:*:*:secret:A4B*'],
                },
              ],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_3 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass for IAM policies that have a statement with "Effect": "Allow" with restricted "Action" over "Resource": "*"', async () => {
      const data = {
        queryawsIamPolicy: [
          {
            id: cuid(),
            name: 'AdministratorAccess-Amplify',
            policyContent: {
              statement: [
                {
                  effect: 'Allow',
                  action: [
                    'secretsmanager:DeleteSecret',
                    'secretsmanager:GetSecretValue',
                    'secretsmanager:UpdateSecret',
                  ],
                  resource: ['*'],
                },
              ],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_3 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail for IAM policies that allow full "*:*" administrative privileges', async () => {
      const data = {
        queryawsIamPolicy: [
          {
            id: cuid(),
            name: 'AdministratorAccess-Amplify',
            policyContent: {
              statement: [
                {
                  effect: 'Allow',
                  action: ['*'],
                  resource: ['*'],
                },
              ],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_3 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when IAM policies that allow full "*:*" administrative privileges for AdministratorAccess policy', async () => {
      const data = {
        queryawsIamPolicy: [
          {
            id: cuid(),
            name: 'AdministratorAccess',
            policyContent: {
              statement: [
                {
                  effect: 'Allow',
                  action: ['*'],
                  resource: ['*'],
                },
              ],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_3 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('IAM Check 4: Hardware MFA should be enabled for the root user', () => {
    test('Should fail when a root account has not a mfa hardware device active', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            mfaActive: false,
            mfaDevices: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_4 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when a root account has a mfa virtual device active', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            mfaActive: true,
            accountId: '123456',
            virtualMfaDevices: [
              {
                serialNumber: 'arn:aws:iam::123456:mfa/root-account-mfa-device',
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_4 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when a root account has a mfa hardware device active', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            mfaActive: true,
            accountId: '123456',
            virtualMfaDevices: [
              {
                serialNumber: 'arn:aws:iam::123456:mfa/some-account-mfa-device',
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_4 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('IAM Check 5: Virtual MFA should be enabled for the root user', () => {
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
        Aws_PCI_DSS_321_IAM_5 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.FAIL)
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
        Aws_PCI_DSS_321_IAM_5 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('IAM Check 6: MFA should be enabled for all IAM users', () => {
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
        Aws_PCI_DSS_321_IAM_6 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when a user has no active password', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            passwordEnabled: false,
            mfaActive: true,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_6 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
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
        Aws_PCI_DSS_321_IAM_6 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('IAM Check 7: IAM user credentials should be disabled if not used within a predefined number of days', () => {
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
        Aws_PCI_DSS_321_IAM_7 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.FAIL)
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
        Aws_PCI_DSS_321_IAM_7 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.FAIL)
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
        Aws_PCI_DSS_321_IAM_7 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass given no password last used AND no access key data', async () => {
      const data = {
        queryawsIamUser: [
          {
            id: cuid(),
            passwordLastUsed: '',
            accessKeyData: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_7 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('IAM Check 8: Password policies for IAM users should have strong configurations', () => {
    test('Should fail given a password policy without required uppercase letter', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireUppercaseCharacters: false,
            requireLowercaseCharacters: true,
            requireNumbers: true,
            minimumPasswordLength: 24,
            passwordReusePrevention: 24,
            maxPasswordAge: 30,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_8 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass given a password policy that must have at least one uppercase letter', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireUppercaseCharacters: true,
            requireLowercaseCharacters: true,
            requireNumbers: true,
            minimumPasswordLength: 24,
            passwordReusePrevention: 24,
            maxPasswordAge: 30,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_8 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail given a password policy without required lowercase letter', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireUppercaseCharacters: true,
            requireLowercaseCharacters: false,
            requireNumbers: true,
            minimumPasswordLength: 24,
            passwordReusePrevention: 24,
            maxPasswordAge: 30,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_8 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass given a password policy that must have at least one lowercase letter', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireUppercaseCharacters: true,
            requireLowercaseCharacters: true,
            requireNumbers: true,
            minimumPasswordLength: 24,
            passwordReusePrevention: 24,
            maxPasswordAge: 30,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_8 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail given a password policy without required numbers', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireUppercaseCharacters: true,
            requireLowercaseCharacters: true,
            requireNumbers: false,
            minimumPasswordLength: 24,
            passwordReusePrevention: 24,
            maxPasswordAge: 30,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_8 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass given a password policy that must have at least one number', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireUppercaseCharacters: true,
            requireLowercaseCharacters: true,
            requireNumbers: true,
            minimumPasswordLength: 24,
            passwordReusePrevention: 24,
            maxPasswordAge: 30,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_8 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail given a password policy length of 13', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            minimumPasswordLength: 13,
            requireUppercaseCharacters: true,
            requireLowercaseCharacters: true,
            requireNumbers: true,
            passwordReusePrevention: 24,
            maxPasswordAge: 30,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_8 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass given a password policy length of 14', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            minimumPasswordLength: 14,
            requireUppercaseCharacters: true,
            requireLowercaseCharacters: true,
            requireNumbers: true,
            passwordReusePrevention: 24,
            maxPasswordAge: 30,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_8 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail if the number of previous passwords is less than 24', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            __typename: 'awsIamPasswordPolicy',
            passwordReusePrevention: 6,
            minimumPasswordLength: 14,
            requireUppercaseCharacters: true,
            requireLowercaseCharacters: true,
            requireNumbers: true,
            maxPasswordAge: 30,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_8 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass if the number of previous passwords is more than 24', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            __typename: 'awsIamPasswordPolicy',
            passwordReusePrevention: 25,
            minimumPasswordLength: 14,
            requireUppercaseCharacters: true,
            requireLowercaseCharacters: true,
            requireNumbers: true,
            maxPasswordAge: 30,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_8 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail given a password that expires after 90 days or more', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            __typename: 'awsIamPasswordPolicy',
            maxPasswordAge: 180,
            minimumPasswordLength: 14,
            requireUppercaseCharacters: true,
            requireLowercaseCharacters: true,
            requireNumbers: true,
            passwordReusePrevention: 24,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_8 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass given a password that expires within 90 days or less', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            __typename: 'awsIamPasswordPolicy',
            minimumPasswordLength: 14,
            requireUppercaseCharacters: true,
            requireLowercaseCharacters: true,
            requireNumbers: true,
            passwordReusePrevention: 24,
            maxPasswordAge: 30,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_IAM_8 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('IAM Check 5: Virtual MFA should be enabled for the root user', () => {
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
        Aws_PCI_DSS_321_IAM_5 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.FAIL)
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
        Aws_PCI_DSS_321_IAM_5 as Rule,
        { ...data } as any
      )
      expect(processedRule.result).toBe(Result.PASS)
    })
  })
})
