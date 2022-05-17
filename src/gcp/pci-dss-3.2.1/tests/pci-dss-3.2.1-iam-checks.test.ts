import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_PCI_DSS_321_IAM_1 from '../rules/pci-dss-3.2.1-iam-check-1'
import Gcp_PCI_DSS_321_IAM_2 from '../rules/pci-dss-3.2.1-iam-check-2'

export interface Bindings {
  members: string[]
  role?: string
}

export interface IamPolicy {
  kmsCryptoKey?: string
  bindings: Bindings[]
}

export interface ApiKey {
  id: string
}

export interface QuerygcpProject {
  id: string
  iamPolicies?: IamPolicy[]
  apiKeys?: ApiKey[]
}

export interface QuerygcpIamPolicy {
  id: string
  bindings: Bindings[]
}

export interface PCIQueryResponse {
  querygcpIamPolicy?: QuerygcpIamPolicy[]
  querygcpProject?: QuerygcpProject[]
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'PCI'} )
  })


  describe('IAM check 1: IAM users should not have both KMS admin and any of the KMS encrypter/decrypter roles', () => {
    const getTestRuleFixture = (
      role: string,
      members: string[]
    ): PCIQueryResponse => {
      return {
        querygcpIamPolicy: [
          {
            id: cuid(),
            bindings: [
              {
                role: 'roles/cloudkms.admin',
                members: ['user:user1@autocloud.dev']
              },
              {
                role,
                members,
              },
            ],
          },
        ],
      }
    }

    const test111Rule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_IAM_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a user account with kms admin role and without any cryptoKey roles', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        'roles/editor', ['user:user1@autocloud.dev']
      )
      await test111Rule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a user account with kms admin role and cryptoKeyEncrypterDecrypter role', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        'roles/cloudkms.cryptoKeyEncrypterDecrypter', ['user:user1@autocloud.dev']
      )
      await test111Rule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with a user account with kms admin role and cryptoKeyEncrypter role', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        'roles/cloudkms.cryptoKeyEncrypter', ['user:user1@autocloud.dev']
      )
      await test111Rule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with a user account with kms admin role and cryptoKeyDecrypter role', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        'roles/cloudkms.cryptoKeyDecrypter', ['user:user1@autocloud.dev']
      )
      await test111Rule(data, Result.FAIL)
    })

  })

  describe('IAM check 2: IAM users should not have project-level "Service Account User" or "Service Account Token Creator" roles', () => {
    const getTestRuleFixture = (
      role: string,
      projectMembers: string[]
    ): PCIQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            iamPolicies: [
              {
                bindings: [
                  {
                    role,
                    members: projectMembers,
                  },
                ],
              },
            ],
          },
        ],
      }
    }

    const test16Rule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_IAM_2 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with user accounts with securityReviewer role', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        'roles/iam.securityReviewer',
        ['user:user1@autocloud.dev', 'user:user2@autocloud.dev']
      )
      await test16Rule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with user accounts with serviceAccountUser role', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        'roles/iam.serviceAccountUser',
        ['user:user1@autocloud.dev', 'user:user2@autocloud.dev']
      )
      await test16Rule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with user accounts with serviceAccountTokenCreator role', async () => {
      const data: PCIQueryResponse = getTestRuleFixture(
        'roles/iam.serviceAccountTokenCreator',
        ['user:user1@autocloud.dev', 'user:user2@autocloud.dev']
      )
      await test16Rule(data, Result.FAIL)
    })
  })
})
