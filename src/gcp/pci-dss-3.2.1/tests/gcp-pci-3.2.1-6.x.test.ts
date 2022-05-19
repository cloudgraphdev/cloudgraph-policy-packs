import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_PCI_DSS_321_61 from '../rules/pci-dss-3.2.1-6.1'

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

export interface CIS6xQueryResponse {
  querygcpKmsKeyRing?: QuerygcpKmsKeyRing[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'PCI'} )
  })

  describe('GCP PCI 6.1 KMS keys should not be anonymously or publicly accessible', () => {
    const getTest61RuleFixture = (
      members: string[]
    ): CIS6xQueryResponse => {
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

    const test61Rule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_61 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with no anonymous user accounts', async () => {
      const data: CIS6xQueryResponse = getTest61RuleFixture(
        ['user:user1@autocloud.dev', 'user:user2@autocloud.dev']
      )
      await test61Rule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with allUsers permissions', async () => {
      const data: CIS6xQueryResponse = getTest61RuleFixture(
        ['allUsers']
      )
      await test61Rule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with allAuthenticatedUsers permissions', async () => {
      const data: CIS6xQueryResponse = getTest61RuleFixture(
        ['allAuthenticatedUsers']
      )
      await test61Rule(data, Result.FAIL)
    })
  })

})
