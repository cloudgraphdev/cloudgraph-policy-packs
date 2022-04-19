import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_NIST_800_53_111 from '../rules/aws-nist-800-53-rev4-11.1'
import Aws_NIST_800_53_112 from '../rules/aws-nist-800-53-rev4-11.2'

export interface Logging {
  enabled: boolean
}

export interface DataResource {
  type: string
}

export interface EventSelector {
  readWriteType?: string
  includeManagementEvents?: boolean
  dataResources?: DataResource[]
}

export interface Cloudtrail {
  isMultiRegionTrail?: string
  eventSelectors?: EventSelector[]
  includeGlobalServiceEvents?: string
}

export interface QueryawsCloudfront {
  id: string
  logging: Logging
}

export interface QueryawsAccount {
  id: string
  cloudtrail: Cloudtrail[]
}

export interface QueryawsCloudtrail {
  id: string
  eventSelectors?: EventSelector[]
}

export interface QueryawsAlb {
  id: string
  accessLogsEnabled: string
}

export interface QueryawsElb {
  id: string
  accessLogs: string
}

export interface NIS6xQueryResponse {
  queryawsCloudfront?: QueryawsCloudfront[]
  queryawsAccount?: QueryawsAccount[]
  queryawsCloudtrail?: QueryawsCloudtrail[]
  queryawsAlb?: QueryawsAlb[]
  queryawsElb?: QueryawsElb[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'NIST',
    })
  })

  //11.X
  describe(' AWS 11.1 ECS task definitions should limit memory usage for containers', () => {
    const getTestRuleFixture = (memory: string|null|undefined): any => {
      return {
        queryawsEcsTaskDefinition: [
          {
            id: cuid(),
            memory
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: any,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_111 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('Container memory is within the acceptable limit', async () => {
      const data: any = getTestRuleFixture('512')
      await testRule(data, Result.PASS)
    })

    test('Container memory is within the acceptable limit', async () => {
      const data: any = getTestRuleFixture('256')
      await testRule(data, Result.PASS)
    })

    test('Container memory cannot be null or undefined', async () => {
      const data: any = getTestRuleFixture(null)
      await testRule(data, Result.FAIL)
    })

    test('Container memory cannot be null or undefined', async () => {
      const data: any = getTestRuleFixture(undefined)
      await testRule(data, Result.FAIL)
    })
  })

  describe(' AWS 11.2 ECS task definitions should set CPU limit for containers', () => {
    const getTestRuleFixture = (cpu: string|null|undefined): any => {
      return {
        queryawsEcsTaskDefinition: [
          {
            id: cuid(),
            cpu
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: any,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_112 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('CPU limit is within the acceptable limit', async () => {
      const data: any = getTestRuleFixture('512')
      await testRule(data, Result.PASS)
    })

    test('CPU limit is within the acceptable limit', async () => {
      const data: any = getTestRuleFixture('256')
      await testRule(data, Result.PASS)
    })

    test('CPU limit cannot be null or undefined', async () => {
      const data: any = getTestRuleFixture(null)
      await testRule(data, Result.FAIL)
    })

    test('CPU limit cannot be null or undefined', async () => {
      const data: any = getTestRuleFixture(undefined)
      await testRule(data, Result.FAIL)
    })
  })

})
