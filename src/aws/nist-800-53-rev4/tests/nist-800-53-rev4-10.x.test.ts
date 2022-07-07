import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Aws_NIST_800_53_101 from '../rules/aws-nist-800-53-rev4-10.1'
import Aws_NIST_800_53_102 from '../rules/aws-nist-800-53-rev4-10.2'
import Aws_NIST_800_53_103 from '../rules/aws-nist-800-53-rev4-10.3'
import Aws_NIST_800_53_104 from '../rules/aws-nist-800-53-rev4-10.4'
import Aws_NIST_800_53_105 from '../rules/aws-nist-800-53-rev4-10.5'
import Aws_NIST_800_53_106 from '../rules/aws-nist-800-53-rev4-10.6'
import Aws_NIST_800_53_107 from '../rules/aws-nist-800-53-rev4-10.7'
import Aws_NIST_800_53_108 from '../rules/aws-nist-800-53-rev4-10.8'

export interface AccessKeyData {
  status: string
  lastRotated: string
}

export interface QueryawsIamUser {
  id: string
  accessKeyData: AccessKeyData[]
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

export interface NIST10xQueryResponse {
  queryawsIamUser?: QueryawsIamUser[]
  queryawsIamPasswordPolicy?: QueryawsIamPasswordPolicy[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'NIST')
  })

  describe('AWS NIST 10.1 IAM password policies should expire passwords within 90 days', () => {
    const getTestRuleFixture = (
      expirePasswords: boolean,
      maxPasswordAge: number
    ): NIST10xQueryResponse => {
      return {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            expirePasswords,
            maxPasswordAge,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: NIST10xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_101 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there is an inbound rule that password expire within 90 days', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(true, 90)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule that password expire in more than 90 days', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(true, 91)
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with password expiration disabled', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(false, 0)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 10.2 IAM password policies should have a minimum length of 7 and include both alphabetic and numeric characters', () => {
    const getTestRuleFixture = (
      minimumPasswordLength: number,
      requireNumbers: boolean,
    ): NIST10xQueryResponse => {
      return {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            minimumPasswordLength,
            requireNumbers,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: NIST10xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_102 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there is an inbound rule with minimum length of 7 and include both alphabetic and numeric characters', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(7, true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with minimum length less than 7', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(6, true)
      await testRule(data, Result.FAIL)
    })

    test('Security issue when there is an inbound rule that does not include alphabetic or numeric characters', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(7, false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 10.3 IAM password policies should prevent reuse of previously used passwords', () => {
    const getTestRuleFixture = (
      passwordReusePrevention: number
    ): NIST10xQueryResponse => {
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
      data: NIST10xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_103 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there is an inbound rule with password reuse prevention greater than or equal to 24', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(24)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with password reuse prevention less than 24', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(23)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 10.4 IAM password policies should prevent reuse of the four previously used passwords', () => {
    const getTestRuleFixture = (
      passwordReusePrevention: number
    ): NIST10xQueryResponse => {
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
      data: NIST10xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_104 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there is an inbound rule with password reuse prevention equal to 4', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(4)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with password reuse prevention greater than 4', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(5)
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with password reuse prevention less than 4', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(3)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 10.5 IAM password policies should require at least one lowercase character', () => {
    const getTestRuleFixture = (
      requireLowercaseCharacters: boolean
    ): NIST10xQueryResponse => {
      return {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireLowercaseCharacters,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: NIST10xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_105 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there is an inbound rule that require at least one lowercase character', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule that NOT require at least one lowercase character', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 10.6 IAM password policies should require at least one number', () => {
    const getTestRuleFixture = (
      requireNumbers: boolean
    ): NIST10xQueryResponse => {
      return {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireNumbers,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: NIST10xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_106 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there is an inbound rule that require at least one number', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule that NOT require at least one number', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 10.7 IAM password policies should require at least one symbol', () => {
    const getTestRuleFixture = (
      requireSymbols: boolean
    ): NIST10xQueryResponse => {
      return {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireSymbols,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: NIST10xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_107 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there is an inbound rule that require at least one symbol', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule that NOT require at least one symbol', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 10.8 IAM password policies should require at least one uppercase character', () => {
    const getTestRuleFixture = (
      requireUppercaseCharacters: boolean
    ): NIST10xQueryResponse => {
      return {
        queryawsIamPasswordPolicy: [
          {
            id: cuid(),
            requireUppercaseCharacters,
          },
        ]
      }
    }

    // Act
    const testRule = async (
      data: NIST10xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_108 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }
      
    test('No Security Issue when there is an inbound rule that require at least one uppercase character', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule that NOT require at least one uppercase character', async () => {
      const data: NIST10xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })
})
