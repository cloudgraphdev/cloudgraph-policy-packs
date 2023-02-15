import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Aws_CIS_140_211 from '../rules/aws-cis-1.4.0-2.1.1'
import Aws_CIS_140_212 from '../rules/aws-cis-1.4.0-2.1.2'
import Aws_CIS_140_213 from '../rules/aws-cis-1.4.0-2.1.3'
import Aws_CIS_140_215_1 from '../rules/aws-cis-1.4.0-2.1.5.1'
import Aws_CIS_140_215_2 from '../rules/aws-cis-1.4.0-2.1.5.2'
import Aws_CIS_140_231 from '../rules/aws-cis-1.4.0-2.3.1'

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

export interface QueryawsRdsDbInstance {
  id: string
  encrypted: boolean
}

export interface EncryptionRule {
  sseAlgorithm: string
}
export interface QueryawsS3 {
  id: string
  policy?: Policy
  versioning?: string
  mfa?: string
  blockPublicAcls?: string
  ignorePublicAcls?: string
  blockPublicPolicy?: string
  restrictPublicBuckets?: string
  accountLevelBlockPublicAcls?: string,
  accountLevelIgnorePublicAcls?: string,
  accountLevelBlockPublicPolicy?: string,
  accountLevelRestrictPublicBuckets?: string
  encrypted?: string
  encryptionRules?: EncryptionRule[]
}
export interface CIS2xQueryResponse {
  queryawsS3?: QueryawsS3[]
  queryawsRdsDbInstance?: QueryawsRdsDbInstance[]
}

describe('CIS Amazon Web Services Foundations: 1.4.0', () => {
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
        Aws_CIS_140_211 as Rule,
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
        Aws_CIS_140_212 as Rule,
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
        's3:*',
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
        's3:*',
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
        's3:*',
        principal,
        condition
      )

      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 2.1.3 Ensure MFA Delete is enable on S3 buckets', () => {
    const getTestRuleFixture = (
      versioning: string,
      mfa: string
    ): CIS2xQueryResponse => {
      return {
        queryawsS3: [
          {
            id: cuid(),
            versioning,
            mfa,
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
        Aws_CIS_140_213 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Versioning and MFA Delete is enable on S3 buckets', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture('Enabled', 'Enabled')
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when Versioning is disabled on S3 buckets', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture('Disabled', 'Enabled')
      await testRule(data, Result.FAIL)
    })

    test('No Security Issue when MFA Delete is disabled on S3 buckets', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture('Enabled', 'Disabled')
      await testRule(data, Result.FAIL)
    })

    test('No Security Issue when Versioning and MFA Delete are disabled on S3 buckets', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'Disabled',
        'Disabled'
      )
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 2.1.5.1 Ensure that S3 Buckets are configured with Block public access (account settings)', () => {
    const getTestRuleFixture = (
      accountLevelBlockPublicAcls: string,
      accountLevelIgnorePublicAcls: string,
      accountLevelBlockPublicPolicy: string,
      accountLevelRestrictPublicBuckets: string,
    ): CIS2xQueryResponse => {
      return {
        queryawsS3: [
          {
            id: cuid(),
            accountLevelBlockPublicAcls,
            accountLevelIgnorePublicAcls,
            accountLevelBlockPublicPolicy,
            accountLevelRestrictPublicBuckets,
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
        Aws_CIS_140_215_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when S3 Account Level is configured with Block public access', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'Yes',
        'Yes',
        'Yes',
        'Yes'
      )
      await testRule(data, Result.PASS)
    })

    test('Security Issue when S3 Account Level is not configured with Block public access', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'No',
        'No',
        'No',
        'No'
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when S3 Account Level have a Block public access with blockPublicAcls set to No', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'No',
        'Yes',
        'Yes',
        'Yes'
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when S3 Account Level have a Block public access with ignorePublicAcls set to No', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'Yes',
        'No',
        'Yes',
        'Yes'
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when S3 Account Level have a Block public access with blockPublicPolicy set to No', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'Yes',
        'Yes',
        'No',
        'Yes'
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when S3 Account Level have a Block public access with restrictPublicBuckets set to No', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'Yes',
        'Yes',
        'Yes',
        'No'
      )
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 2.1.5.2 Ensure that S3 Buckets are configured with Block public access (bucket settings)', () => {
    const getTestRuleFixture = (
      blockPublicAcls: string,
      ignorePublicAcls: string,
      blockPublicPolicy: string,
      restrictPublicBuckets: string
    ): CIS2xQueryResponse => {
      return {
        queryawsS3: [
          {
            id: cuid(),
            blockPublicAcls,
            ignorePublicAcls,
            blockPublicPolicy,
            restrictPublicBuckets,
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
        Aws_CIS_140_215_2 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when S3 Buckets are configured with Block public access', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'Yes',
        'Yes',
        'Yes',
        'Yes'
      )
      await testRule(data, Result.PASS)
    })

    test('Security Issue when S3 Buckets are not configured with Block public access', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'No',
        'No',
        'No',
        'No'
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when S3 Buckets have a Block public access with blockPublicAcls set to No', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'No',
        'Yes',
        'Yes',
        'Yes'
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when S3 Buckets have a Block public access with ignorePublicAcls set to No', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'Yes',
        'No',
        'Yes',
        'Yes'
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when S3 Buckets have a Block public access with blockPublicPolicy set to No', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'Yes',
        'Yes',
        'No',
        'Yes'
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when S3 Buckets have a Block public access with restrictPublicBuckets set to No', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(
        'Yes',
        'Yes',
        'Yes',
        'No'
      )
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 2.3.1 Ensure that encryption is enabled for RDS Instances', () => {
    const getTestRuleFixture = (encrypted: boolean): CIS2xQueryResponse => {
      return {
        queryawsRdsDbInstance: [
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
        Aws_CIS_140_231 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when RDS instances are encrypted', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when RDS instances are not encrypted', async () => {
      const data: CIS2xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })
})
