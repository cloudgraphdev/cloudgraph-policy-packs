import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Aws_CIS_130_211 from '../rules/aws-cis-1.3.0-2.1.1'
import Aws_CIS_130_212 from '../rules/aws-cis-1.3.0-2.1.2'
import Aws_CIS_130_221 from '../rules/aws-cis-1.3.0-2.2.1'

export interface Condition {
  key: string
  value: string[]
}

export interface Principal {
  key: string
  value: string[]
}

export interface Statement {
  effect: string
  action: string[]
  principal: Principal[]
  condition: Condition[]
}

export interface Policy {
  statement: Statement[]
}

export interface Subscription {
  protocol: string
  endpoint: string
}

export interface EncryptionRule {
  sseAlgorithm: string
}

export interface QueryawsS3 {
  id: string
  policy?: Policy
  encrypted?: string
  encryptionRules?: EncryptionRule[]
}

export interface QueryawsEbs {
  id: string
  encrypted: boolean
}

export interface CIS2xQueryResponse {
  queryawsS3?: QueryawsS3[]
  queryawsEbs?: QueryawsEbs[]
}

describe('CIS Amazon Web Services Foundations: 1.3.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'CIS')
  })

  describe('AWS CIS 2.1.1 Ensure all S3 buckets employ encryption-at-rest', () => {
    const getTestRuleFixture = (
      encrypted: string,
      sseAlgorithm: string
      ): CIS2xQueryResponse => {
      return {
        queryawsS3: [
          {
            id: cuid(),
            encrypted,
            encryptionRules: [
              {
                sseAlgorithm
              }
            ]
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_130_211 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when S3 bucket server-side default encryption is set to AES256', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture('Yes', 'AES256')
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when S3 bucket server-side default encryption is set to AES256', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture('Yes', 'aws:kms')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when S3 bucket server-side encryption is not enabled', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture('No', '')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 2.1.2 Ensure S3 Bucket Policy allows HTTPS requests', () => {
    const getTestRuleFixture = (
      effect: string,
      action: string,
      principal: Principal,
      condition: Condition
    ): CIS2xQueryResponse => {
      return {
        queryawsS3: [
          {
            id: cuid(),
            policy: {
              statement: [
                {
                  effect,
                  action: [action],
                  principal: [principal],
                  condition: [condition],
                },
              ],
            },
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_130_212 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when S3 bucket policies only allow requests that use HTTPS', async () => {
      const principal: Principal = {
        key: 'AWS',
        value: ['*'],
      }
      const condition: Condition = {
        key: 'aws:SecureTransport',
        value: ['false'],
      }
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'Deny',
        '*',
        principal,
        condition
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when S3 bucket policy does not have SecureTransport enabled', async () => {
      const principal: Principal = {
        key: 'AWS',
        value: ['arn:aws:iam::111122223333:root'],
      }
      const condition: Condition = {
        key: 'aws:SecureTransport',
        value: ['false'],
      }
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'Allow',
        '*',
        principal,
        condition
      )

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when S3 bucket policy have SecureTransport enabled but grants permission to any public anonymous users', async () => {
      const principal: Principal = { key: '', value: ['*'] }
      const condition: Condition = {
        key: 'aws:SecureTransport',
        value: ['true'],
      }
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'Allow',
        '*',
        principal,
        condition
      )

      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 2.2.1 Ensure EBS volume encryption is enabled', () => {
    const getTestRuleFixture = (encrypted: boolean): CIS2xQueryResponse => {
      return {
        queryawsEbs: [
          {
            id: cuid(),
            encrypted,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_130_221 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when EBS volume encryption is enabled', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when EBS volume encryption is not enabled', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })
})