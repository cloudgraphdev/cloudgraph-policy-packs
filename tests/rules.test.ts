import CloudGraph from '@cloudgraph/sdk'

import { Rule, RuleResult } from '@cloudgraph/sdk/dist/src/rules-engine/types'
import RulesProvider from '../../sdk/dist/src/rules-engine'

import Aws_CIS_120_19 from '../src/rules/aws-cis-1.2.0-1.9'

describe('CIS Amazon Web Services Foundations: 1.2.0', () => {
  let rulesEngine: RulesProvider
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine([Aws_CIS_120_19 as Rule], {}, '')
  })

  describe('AWS CIS 1.9 Ensure IAM password policy requires minimum length of 14 or greater', () => {
    test('Should fail given a password policy length of 13', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: 'iam:region:aws-global-account:632941798677-aws-iam-password-policy-ckvmuy28g0000ats15vhwgane',
            __typename: 'awsIamPasswordPolicy',
            minimumPasswordLength: 13,
          },
        ],
      }

      const result = await rulesEngine.processRule(
        Aws_CIS_120_19 as Rule,
        { data } as any
      )
      expect(result).toBe(RuleResult.DOESNT_MATCH)
    })

    test('Should pass given a password policy length of 14', async () => {
      const data = {
        queryawsIamPasswordPolicy: [
          {
            id: 'iam:region:aws-global-account:632941798677-aws-iam-password-policy-ckvmuy28g0000ats15vhwgane',
            __typename: 'awsIamPasswordPolicy',
            minimumPasswordLength: 14,
          },
        ],
      }

      const result = await rulesEngine.processRule(
        Aws_CIS_120_19 as Rule,
        { data } as any
      )
      expect(result).toBe(RuleResult.MATCHES)
    })
  })
})
