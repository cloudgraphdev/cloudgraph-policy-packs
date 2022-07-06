import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_PCI_DSS_321_KMS_1 from '../rules/pci-dss-3.2.1-kms-check-1'
import { initRuleEngine } from '../../../utils/test'

export interface Bindings {
  members: string[]
  role?: string
}
export interface IamPolicy {
  kmsCryptoKey?: string
  bindings: Bindings[]
}

export interface CryptoKey {
  rotationPeriod?: string
  nextRotationTime?: string
  iamPolicy?: IamPolicy[]
}

export interface QuerygcpKmsKeyRing {
  id: string
  kmsCryptoKeys: CryptoKey[]
}

export interface CISKMSQueryResponse {
  querygcpKmsKeyRing?: QuerygcpKmsKeyRing[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('gcp', 'PCI')
  })

  describe('KMS Check 1: KMS keys should not be anonymously or publicly accessible', () => {
    const getTestKMS1RuleFixture = (
      members: string[]
    ): CISKMSQueryResponse => {
      return {
        querygcpKmsKeyRing: [
          {
            id: cuid(),
            kmsCryptoKeys: [
              {
                iamPolicy: [
                  {
                    bindings: [
                      {
                        members,
                      },
                    ],
                  },
                ],
              }
            ],
          },
        ],
      }
    }

    const testKMS1Rule = async (
      data: CISKMSQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_KMS_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with no anonymous user accounts', async () => {
      const data: CISKMSQueryResponse = getTestKMS1RuleFixture(
        ['user:user1@autocloud.dev', 'user:user2@autocloud.dev']
      )
      await testKMS1Rule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with allUsers permissions', async () => {
      const data: CISKMSQueryResponse = getTestKMS1RuleFixture(
        ['allUsers']
      )
      await testKMS1Rule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with allAuthenticatedUsers permissions', async () => {
      const data: CISKMSQueryResponse = getTestKMS1RuleFixture(
        ['allAuthenticatedUsers']
      )
      await testKMS1Rule(data, Result.FAIL)
    })
  })

})
