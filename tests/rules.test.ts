import cuid from 'cuid'
import CloudGraph, { Rule, Engine } from '@cloudgraph/sdk'

import Aws_CIS_120_15 from '../src/rules/aws-cis-1.2.0-1.5'
import Aws_CIS_120_16 from '../src/rules/aws-cis-1.2.0-1.6'
import Aws_CIS_120_17 from '../src/rules/aws-cis-1.2.0-1.7'
import Aws_CIS_120_18 from '../src/rules/aws-cis-1.2.0-1.8'
import Aws_CIS_120_19 from '../src/rules/aws-cis-1.2.0-1.9'

describe('CIS Amazon Web Services Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine()
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
})
