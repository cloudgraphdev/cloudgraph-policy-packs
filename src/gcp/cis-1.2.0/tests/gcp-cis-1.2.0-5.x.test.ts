/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Gcp_CIS_120_51 from '../rules/gcp-cis-1.2.0-5.1'
import Gcp_CIS_120_52 from '../rules/gcp-cis-1.2.0-5.2'

export interface UniformBucketLevelAccess {
  enabled: boolean
}

export interface IamConfiguration {
  uniformBucketLevelAccess: UniformBucketLevelAccess
}

export interface Binding {
  role: string
  members: string[]
}

export interface IamPolicy {
  bindings: Binding[]
}

export interface QuerygcpStorageBucket {
  id: string
  iamConfiguration?: IamConfiguration
  iamPolicy?: IamPolicy[]
}

export interface CIS5xQueryResponse {
  querygcpStorageBucket?: QuerygcpStorageBucket[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'CIS'} )
  })

  describe('GCP CIS 5.1 Ensure that Cloud Storage bucket is not anonymously or publicly accessible', () => {
    const getTest51RuleFixture = (members: string[]): CIS5xQueryResponse => {
      return {
        querygcpStorageBucket: [
          {
            id: cuid(),
            iamPolicy: [
              {
                bindings: [
                  {
                    role: 'dummy-role',
                    members,
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
        Gcp_CIS_120_51 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when role members are not allUsers or allAuthenticatedUsers', async () => {
      const data: CIS5xQueryResponse = getTest51RuleFixture([
        'projectViewer:dummy-sandbox',
      ])
      await test51Rule(data, Result.PASS)
    })

    test('Security Issue when role member is allUsers', async () => {
      const data: CIS5xQueryResponse = getTest51RuleFixture(['allUsers'])
      await test51Rule(data, Result.FAIL)
    })

    test('Security Issue when role member is allAuthenticatedUsers', async () => {
      const data: CIS5xQueryResponse = getTest51RuleFixture([
        'allAuthenticatedUsers',
      ])
      await test51Rule(data, Result.FAIL)
    })

    test('Security Issue when role members contains allUsers and allAuthenticatedUsers', async () => {
      const data: CIS5xQueryResponse = getTest51RuleFixture([
        'dummy',
        'allUsers',
        'allAuthenticatedUsers',
      ])
      await test51Rule(data, Result.FAIL)
    })

    test('Security Issue when role members contains allUsers (multiple iamPolicies)', async () => {
      const data: CIS5xQueryResponse = {
        querygcpStorageBucket: [
          {
            id: cuid(),
            iamPolicy: [
              {
                bindings: [
                  {
                    role: 'dummy-role1',
                    members: ['dummy1'],
                  },
                ],
              },
              {
                bindings: [
                  {
                    role: 'dummy-role2',
                    members: ['dummy2'],
                  },
                  {
                    role: 'dummy-role3',
                    members: ['allUsers'],
                  },
                ],
              },
            ],
          },
        ],
      }
      await test51Rule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 5.2 Ensure that Cloud Storage buckets have uniform bucket-level access enabled', () => {
    const getTest52RuleFixture = (
      uniformBucketLevelAccess: boolean
    ): CIS5xQueryResponse => {
      return {
        querygcpStorageBucket: [
          {
            id: cuid(),
            iamConfiguration: {
              uniformBucketLevelAccess: {
                enabled: uniformBucketLevelAccess,
              },
            },
          },
        ],
      }
    }

    const test52Rule = async (
      data: CIS5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_52 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when uniformBucketLevelAccess is true', async () => {
      const data: CIS5xQueryResponse = getTest52RuleFixture(true)
      await test52Rule(data, Result.PASS)
    })

    test('Security Issue when uniformBucketLevelAccess is false', async () => {
      const data: CIS5xQueryResponse = getTest52RuleFixture(false)
      await test52Rule(data, Result.FAIL)
    })
  })
})
