import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Aws_NIST_800_53_131 from '../rules/aws-nist-800-53-rev4-13.1'
import Aws_NIST_800_53_132 from '../rules/aws-nist-800-53-rev4-13.2'
import Aws_NIST_800_53_133 from '../rules/aws-nist-800-53-rev4-13.3'
import Aws_NIST_800_53_134 from '../rules/aws-nist-800-53-rev4-13.4'

export interface AccessKeyData {
  status: string
  lastRotated: string
}

export interface VirtualMfaDevice {
  serialNumber: string
}

export interface QueryawsIamUser {
  id: string
  accountId?: string
  passwordEnabled?: boolean
  name?: string
  mfaActive?: boolean
  virtualMfaDevices?: VirtualMfaDevice[]
  accessKeyData?: AccessKeyData[]
}

export interface NIST13xQueryResponse {
  queryawsIamUser?: QueryawsIamUser[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'NIST')
  })

  describe('AWS NIST 13.1 IAM multi-factor authentication should be enabled for all IAM users that have a console password', () => {
    const getTestRuleFixture = (
      passwordEnabled: boolean,
      mfaActive: boolean
    ): NIST13xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            passwordEnabled,
            mfaActive
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: NIST13xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_131 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there is an inbound rule with a user that has an active password with an mfa device register', async () => {
      const data: NIST13xQueryResponse = getTestRuleFixture(true, true)
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a user that has no active password', async () => {
      const data: NIST13xQueryResponse = getTestRuleFixture(false, true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with user that has an active password without an mfa device register', async () => {
      const data: NIST13xQueryResponse = getTestRuleFixture(true, false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 13.2 IAM should have hardware MFA enabled for the root account', () => {
    const getTestRuleFixture = (
      mfaActive: boolean
    ): NIST13xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            mfaActive,
            accountId: '123456',
            virtualMfaDevices: [
              {
                serialNumber: 'arn:aws:iam::123456:mfa/some-account-mfa-device'
              }
            ]
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: NIST13xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_132 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there is an inbound rule with a root account that has a mfa hardware device active', async () => {
      const data: NIST13xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a root account that has a mfa hardware device deactivate', async () => {
      const data: NIST13xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 13.3 IAM should have MFA enabled for the root account', () => {
    const getTestRuleFixture = (
      mfaActive: boolean
    ): NIST13xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            name: 'root',
            mfaActive,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: NIST13xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_133 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there is an inbound rule with a root account that has a mfa enabled', async () => {
      const data: NIST13xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a root account that has a mfa disabled', async () => {
      const data: NIST13xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 13.4 IAM users should have MFA (virtual or hardware) enabled', () => {
    const getTestRuleFixture = (
      mfaActive: boolean
    ): NIST13xQueryResponse => {
      return {
        queryawsIamUser: [
          {
            id: cuid(),
            mfaActive,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: NIST13xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_134 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there is an inbound rule with IAM users that has a mfa enabled', async () => {
      const data: NIST13xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with IAM users that has a mfa disabled', async () => {
      const data: NIST13xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })
})