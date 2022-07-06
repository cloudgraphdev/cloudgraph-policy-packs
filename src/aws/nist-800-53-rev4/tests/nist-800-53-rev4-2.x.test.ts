import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Aws_NIST_800_53_21 from '../rules/aws-nist-800-53-rev4-2.1'
import Aws_NIST_800_53_22 from '../rules/aws-nist-800-53-rev4-2.2'
import Aws_NIST_800_53_23 from '../rules/aws-nist-800-53-rev4-2.3'
import Aws_NIST_800_53_24 from '../rules/aws-nist-800-53-rev4-2.4'
import Aws_NIST_800_53_25 from '../rules/aws-nist-800-53-rev4-2.5'


export interface QueryawsRdsCluster {
  id: string
  engine: string
  multiAZ: boolean
}
export interface QueryawsRdsDbInstance {
  id: string
  multiAZ: boolean
}

export interface QueryawsAsg {
  id: string
  availabilityZones: string[]
}

export interface QueryawsElb {
  id: string
  crossZoneLoadBalancing: string
}

export interface QueryawsS3 {
  id: string
  crossRegionReplication: string
}

export interface NIS2xQueryResponse {
  queryawsAsg?: QueryawsAsg[]
  queryawsElb?: QueryawsElb[]
  queryawsRdsCluster?: QueryawsRdsCluster[]
  queryawsRdsDbInstance?: QueryawsRdsDbInstance[]
  queryawsS3?: QueryawsS3[]
}

describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'NIST')
  })

  describe('AWS NIST 2.1 Auto Scaling groups should span two or more availability zones', () => {
    const getTestRuleFixture = (
      availabilityZones: string[]
    ): NIS2xQueryResponse => {
      return {
        queryawsAsg: [
          {
            id: cuid(),
            availabilityZones,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_21 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Auto Scaling groups have span two or more availability zones', async () => {
      const data: NIS2xQueryResponse = getTestRuleFixture([
        'us-east-1',
        'us-east-2',
      ])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when Auto Scaling groups not have span two or more availability zones', async () => {
      const data: NIS2xQueryResponse = getTestRuleFixture(['us-east-1'])
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 2.2 ELBv1 load balancer cross zone load balancing should be enabled', () => {
    const getTestRuleFixture = (
      crossZoneLoadBalancing: string
    ): NIS2xQueryResponse => {
      return {
        queryawsElb: [
          {
            id: cuid(),
            crossZoneLoadBalancing,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_22 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ELBv1 load balancer cross zone load balancing is enabled', async () => {
      const data: NIS2xQueryResponse = getTestRuleFixture('Enabled')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when ELBv1 load balancer cross zone load balancing is not enabled', async () => {
      const data: NIS2xQueryResponse = getTestRuleFixture('Disabled')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 2.3 RDS Aurora cluster multi-AZ should be enabled', () => {
    const getTestRuleFixture = (
      engine: string,
      multiAZ: boolean
    ): NIS2xQueryResponse => {
      return {
        queryawsRdsCluster: [
          {
            id: cuid(),
            engine,
            multiAZ,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_23 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when RDS Aurora cluster multi-AZ is enabled', async () => {
      const data: NIS2xQueryResponse = getTestRuleFixture('aurora-mysql', true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when RDS Aurora cluster multi-AZ is not enabled', async () => {
      const data: NIS2xQueryResponse = getTestRuleFixture('aurora-mysql', false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 2.4 Require Multi Availability Zones turned on for RDS Instances', () => {
    const getTestRuleFixture = (
      multiAZ: boolean
    ): NIS2xQueryResponse => {
      return {
        queryawsRdsDbInstance: [
          {
            id: cuid(),
            multiAZ
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_24 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when RDS Instances has Multi Availability Zones turned on', async () => {
      const data: NIS2xQueryResponse = getTestRuleFixture(true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when RDS Instances has Multi Availability Zones turned off', async () => {
      const data: NIS2xQueryResponse = getTestRuleFixture(false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS NIST 2.5 S3 bucket replication (cross-region or same-region) should be enabled', () => {
    const getTestRuleFixture = (
      crossRegionReplication: string
    ): NIS2xQueryResponse => {
      return {
        queryawsS3: [
          {
            id: cuid(),
            crossRegionReplication
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: NIS2xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_NIST_800_53_25 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when S3 bucket replication is enabled', async () => {
      const data: NIS2xQueryResponse = getTestRuleFixture('Enabled')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when S3 bucket replication is disabled', async () => {
      const data: NIS2xQueryResponse = getTestRuleFixture('Disabled')
      await testRule(data, Result.FAIL)
    })
  })
})
