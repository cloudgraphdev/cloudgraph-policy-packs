import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_CIS_130_31 from '../rules/aws-cis-1.3.0-3.1'
import Aws_CIS_130_32 from '../rules/aws-cis-1.3.0-3.2'
import Aws_CIS_130_33 from '../rules/aws-cis-1.3.0-3.3'
import Aws_CIS_130_34 from '../rules/aws-cis-1.3.0-3.4'
import Aws_CIS_130_35 from '../rules/aws-cis-1.3.0-3.5'
import Aws_CIS_130_36 from '../rules/aws-cis-1.3.0-3.6'
import Aws_CIS_130_37 from '../rules/aws-cis-1.3.0-3.7'
import Aws_CIS_130_38 from '../rules/aws-cis-1.3.0-3.8'
import Aws_CIS_130_39 from '../rules/aws-cis-1.3.0-3.9'
import Aws_CIS_130_310 from '../rules/aws-cis-1.3.0-3.10'
import Aws_CIS_130_311 from '../rules/aws-cis-1.3.0-3.11'

export interface DataResource {
  type: string
}

export interface EventSelector {
  readWriteType?: string
  includeManagementEvents?: boolean
  dataResources?: DataResource[]
}

export interface Status {
  isLogging?: boolean
  latestCloudWatchLogsDeliveryTime?: string | null
  recording?: boolean
  lastStatus?: string
}

export interface Cloudtrail {
  isMultiRegionTrail?: string
  status?: Status
  eventSelectors?: EventSelector[]
}

export interface Principal {
  key?: string
  value?: string[]
}

export interface Statement {
  effect?: string
  principal?: Principal[]
}

export interface Policy {
  statement?: Statement[]
}

export interface S3 {
  policy?: Policy
  logging?: string
}

export interface RecordingGroup {
  allSupported?: boolean
  includeGlobalResourceTypes?: boolean
}

export interface ConfigurationRecorder {
  status?: Status
  recordingGroup?: RecordingGroup
}

export interface FlowLog {
  resourceId?: string
}

export interface QueryawsAccount {
  id: string
  cloudtrail?: Cloudtrail[]
  configurationRecorders?: ConfigurationRecorder[]
}

export interface QueryawsCloudtrail {
  id: string
  logFileValidationEnabled?: string
  cloudWatchLogsLogGroupArn?: string | null
  s3?: S3[]
  status?: Status
  kmsKeyId?: string | null
}

export interface QueryawsKms {
  id: string
  keyManager: string
  keyRotationEnabled: boolean
}

export interface QueryawsVpc {
  id: string
  flowLog: FlowLog[]
}

export interface CIS3xQueryResponse {
  queryawsAccount?: QueryawsAccount[]
  queryawsCloudtrail?: QueryawsCloudtrail[]
  queryawsKms?: QueryawsKms[]
  queryawsVpc?: QueryawsVpc[]
}

describe('CIS Amazon Web Services Foundations: 1.3.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'CIS',
    })
  })

  describe('AWS CIS 3.1 Ensure CloudTrail is enabled in all regions', () => {
    const getTestRuleFixture = (
      isMultiRegionTrail: string,
      isLogging: boolean,
      readWriteType: string,
      includeManagementEvents: boolean
    ): CIS3xQueryResponse => {
      return {
        queryawsAccount: [
          {
            id: cuid(),
            cloudtrail: [
              {
                isMultiRegionTrail,
                status: {
                  isLogging,
                },
                eventSelectors: [
                  {
                    readWriteType,
                    includeManagementEvents,
                  },
                ],
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_130_31 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when a trail has set IsMultiRegionTrail and isLogging as true with at least one Event Selector with IncludeManagementEvents set to true and ReadWriteType set to All', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(
        'Yes',
        true,
        'All',
        true
      )
      await testRule(data, Result.PASS)
    })

    test('Security Issue when a trail has set IsMultiRegionTrail is set to false', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(
        'No',
        true,
        'All',
        true
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when a trail has set isLogging is set to false', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(
        'Yes',
        false,
        'All',
        true
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when a trail has set multi region as true with all read-write type and include management events false', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(
        'Yes',
        true,
        'All',
        false
      )
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there not are any trail', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('', true, '', true)
      const account = data.queryawsAccount?.[0] as QueryawsAccount
      account.cloudtrail = []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 3.2 Ensure CloudTrail log file validation is enabled', () => {
    const getTestRuleFixture = (
      logFileValidationEnabled: string
    ): CIS3xQueryResponse => {
      return {
        queryawsCloudtrail: [
          {
            id: cuid(),
            logFileValidationEnabled,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_130_32 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when a trail has log file validation enabled', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('Yes')
      await testRule(data, Result.PASS)
    })
    test('Security Issue when a trail has log file validation disabled', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('No')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 3.3 Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible', () => {
    const getTestRuleFixture = (
      effect: string,
      key: string,
      value: string[]
    ): CIS3xQueryResponse => {
      return {
        queryawsCloudtrail: [
          {
            id: cuid(),
            s3: [
              {
                policy: {
                  statement: [
                    {
                      effect,
                      principal: [
                        {
                          key,
                          value,
                        },
                      ],
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_130_33 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when a policy contains a statement having an Effect set to Allow and a Principal not set to "*" or {"AWS" : "*"}', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('Allow', 'Service', [
        'cloudtrail.amazonaws.com',
      ])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when a policy contains a statement having an Effect set to Allow and a Principal set to "*"', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('Allow', '', ['*'])
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when a policy contains a statement having an Effect set to Allow and a Principal set to {"AWS" : "*"}', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('Allow', 'AWS', ['*'])
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 3.4 Ensure CloudTrail trails are integrated with CloudWatch Logs', () => {
    const getTestRuleFixture = (
      cloudWatchLogsLogGroupArn: string | null,
      latestCloudWatchLogsDeliveryTime: string | null
    ): CIS3xQueryResponse => {
      return {
        queryawsCloudtrail: [
          {
            id: cuid(),
            cloudWatchLogsLogGroupArn,
            status: {
              latestCloudWatchLogsDeliveryTime,
            },
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_130_34 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when a trail has cloudwatch logs integrated with a delivery date no more than a day', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(cuid(), new Date().toISOString())
      await testRule(data, Result.PASS)
    })

    test('Security Issue when a trail has cloudwatch logs integrated with a delivery date more than a day', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(cuid(), '2021-11-20T16:18:21.724Z')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when a trail does not have cloudwatch logs integrated', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(null, null)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 3.5 Ensure AWS Config is enabled in all regions', () => {
    const getTestRuleFixture = (
      allSupported: boolean,
      includeGlobalResourceTypes: boolean,
      recording: boolean,
      lastStatus: string
    ): CIS3xQueryResponse => {
      return {
        queryawsAccount: [
          {
            id: cuid(),
            configurationRecorders: [
              {
                recordingGroup: {
                  allSupported,
                  includeGlobalResourceTypes,
                },
                status: {
                  recording,
                  lastStatus,
                },
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_130_35 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when a configuration recorder is enabled in all regions', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(true, true, true, 'SUCCESS')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when a configuration recorder has recordingGroup object includes "allSupported": false', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(false, true, true, 'SUCCESS')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when a configuration recorder has recordingGroup object includes "includeGlobalResourceTypes": false', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(true, false, true, 'SUCCESS')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when a configuration recorder has status object includes "lastStatus" not "SUCCESS"', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(true, true, true, 'FAILED')
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when there not are any configurationRecorder', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(true, true, true, 'SUCCESS')
      const account = data.queryawsAccount?.[0] as QueryawsAccount
      account.configurationRecorders = []
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 3.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket', () => {
    const getTestRuleFixture = (
      logging: string
    ): CIS3xQueryResponse => {
      return {
        queryawsCloudtrail: [
          {
            id: cuid(),
            s3: [
              {
                logging,
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_130_36 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when a trails bucket has access logging enabled', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('Enabled')
      await testRule(data, Result.PASS)
    })

    test('Security Issue when a trails bucket has access logging disabled', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('Disabled')
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 3.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs', () => {
    const getTestRuleFixture = (
      kmsKeyId: string | null
    ): CIS3xQueryResponse => {
      return {
        queryawsCloudtrail: [
          {
            id: cuid(),
            kmsKeyId,
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_130_37 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when cloudtrail logs are encrypted using a KMS key', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(cuid())
      await testRule(data, Result.PASS)
    })

    test('Security Issue when cloudtrail logs are not encrypted', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(null)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 3.8 Ensure rotation for customer created CMKs is enabled', () => {
    const getTestRuleFixture = (
      keyManager: string,
      keyRotationEnabled: boolean
    ): CIS3xQueryResponse => {
      return {
        queryawsKms: [
          {
            id: cuid(),
            keyManager,
            keyRotationEnabled
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_130_38 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when rotation is enabled with AWS as a manager', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('AWS', true)
      await testRule(data, Result.PASS)
    })

    test('Security Issue when rotation is disabled with customer as a manager', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('CUSTOMER', false)
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when rotation is disabled with AWS as a manager', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture('AWS', false)
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 3.9 Ensure VPC flow logging is enabled in all VPCs', () => {
    const getTestRuleFixture = (
      flowLog: FlowLog[],
    ): CIS3xQueryResponse => {
      return {
        queryawsVpc: [
          {
            id: cuid(),
            flowLog
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_130_39 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when flow logging is enabled for each VPC', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture([{resourceId: cuid()}])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when flow logging is disabled on one VPC', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture([])
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 3.10 Ensure that Object-level logging for write events is enabled for S3 bucket', () => {
    const getTestRuleFixture = (
      includeManagementEvents: boolean,
      readWriteType: string,
      dataResources: DataResource[]
    ): CIS3xQueryResponse => {
      return {
        queryawsAccount: [
          {
            id: cuid(),
            cloudtrail: [
              {
                eventSelectors: [
                  {
                    includeManagementEvents,
                    readWriteType,
                    dataResources,
                  },
                ],
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_130_310 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when S3 bucket object-level logging for write events is enabled', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(true, 'WriteOnly', [
        { type: 'AWS::S3::Object' },
      ])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when S3 bucket object-level logging for write events is not enabled', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(true, 'WriteOnly', [])
      await testRule(data, Result.FAIL)
    })
  })

  describe('AWS CIS 3.11 Ensure that Object-level logging for read events is enabled for S3 bucket', () => {
    const getTestRuleFixture = (
      includeManagementEvents: boolean,
      readWriteType: string,
      dataResources: DataResource[]
    ): CIS3xQueryResponse => {
      return {
        queryawsAccount: [
          {
            id: cuid(),
            cloudtrail: [
              {
                eventSelectors: [
                  {
                    includeManagementEvents,
                    readWriteType,
                    dataResources,
                  },
                ],
              },
            ],
          },
        ],
      }
    }

    // Act
    const testRule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_130_311 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when S3 bucket object-level logging for read events is enabled', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(true, 'ReadOnly', [
        { type: 'AWS::S3::Object' },
      ])
      await testRule(data, Result.PASS)
    })

    test('Security Issue when S3 bucket object-level logging for read events is not enabled', async () => {
      const data: CIS3xQueryResponse = getTestRuleFixture(true, 'ReadOnly', [])
      await testRule(data, Result.FAIL)
    })
  })
})
