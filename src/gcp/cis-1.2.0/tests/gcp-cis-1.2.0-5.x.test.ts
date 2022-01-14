/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Gcp_CIS_120_52 from '../rules/gcp-cis-1.2.0-5.2'

export interface UniformBucketLevelAccess {
  enabled: boolean
}

export interface IamConfiguration {
  uniformBucketLevelAccess: UniformBucketLevelAccess
}

export interface QuerygcpStorageBucket {
  id: string
  iamConfiguration: IamConfiguration
}

export interface CIS5xQueryResponse {
  querygcpStorageBucket?: QuerygcpStorageBucket[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine('gcp', 'CIS')
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
