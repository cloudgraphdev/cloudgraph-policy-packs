import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_PCI_DSS_321_51 from '../rules/pci-dss-3.2.1-5.1'

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

export interface CIS5xQueryResponse {
  querygcpProject?: QuerygcpProject[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'PCI'} )
  })
  
  describe('GCP PCI 5.1 User-managed service accounts should not have admin privileges', () => {
    const getTest51RuleFixture = (
      role: string,
      projectMembers: string[]
    ): CIS5xQueryResponse => {
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

    const test51Rule = async (
      data: CIS5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_51 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with services accounts with viewer role', async () => {
      const data: CIS5xQueryResponse = getTest51RuleFixture('roles/viewer', [
        'serviceAccount:243921055556-compute@developer.gserviceaccount.com',
        'serviceAccount:243921055556@cloudservices.gserviceaccount.com',
      ])
      await test51Rule(data, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with services accounts with browser role', async () => {
      const data: CIS5xQueryResponse = getTest51RuleFixture('roles/browser', [
        'serviceAccount:243921055556-compute@developer.gserviceaccount.com',
        'serviceAccount:243921055556@cloudservices.gserviceaccount.com',
      ])
      await test51Rule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with services accounts with editor role', async () => {
      const data: CIS5xQueryResponse = getTest51RuleFixture('roles/editor', [
        'serviceAccount:243921055556-compute@developer.gserviceaccount.com',
        'serviceAccount:243921055556@cloudservices.gserviceaccount.com',
      ])
      await test51Rule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with services accounts with owner role', async () => {
      const data: CIS5xQueryResponse = getTest51RuleFixture('roles/owner', [
        'serviceAccount:243921055556-compute@developer.gserviceaccount.com',
        'serviceAccount:243921055556@cloudservices.gserviceaccount.com',
      ])
      await test51Rule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with services accounts with admin role', async () => {
      const data: CIS5xQueryResponse = getTest51RuleFixture(
        'roles/appengine.appAdmin',
        [
          'serviceAccount:243921055556-compute@developer.gserviceaccount.com',
          'serviceAccount:243921055556@cloudservices.gserviceaccount.com',
        ]
      )
      await test51Rule(data, Result.FAIL)
    })
  })

})
