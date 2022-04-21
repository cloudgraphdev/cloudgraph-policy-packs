/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_CIS_120_21 from '../rules/aws-cis-1.2.0-2.1'
import Aws_CIS_120_22 from '../rules/aws-cis-1.2.0-2.2'
import Aws_CIS_120_23 from '../rules/aws-cis-1.2.0-2.3'
import Aws_CIS_120_24 from '../rules/aws-cis-1.2.0-2.4'
import Aws_CIS_120_25 from '../rules/aws-cis-1.2.0-2.5'
import Aws_CIS_120_26 from '../rules/aws-cis-1.2.0-2.6'
import Aws_CIS_120_27 from '../rules/aws-cis-1.2.0-2.7'
import Aws_CIS_120_28 from '../rules/aws-cis-1.2.0-2.8'
import Aws_CIS_120_29 from '../rules/aws-cis-1.2.0-2.9'

describe('CIS Amazon Web Services Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'CIS',
    })
  })
  describe('AWS CIS 2.1 Ensure CloudTrail is enabled in all regions', () => {
    test('Should pass when a trail has set IsMultiRegionTrail and isLogging as true with at least one Event Selector with IncludeManagementEvents set to true and ReadWriteType set to All', async () => {
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            cloudtrail: [
              {
                isMultiRegionTrail: 'Yes',
                status: {
                  isLogging: true,
                },
                eventSelectors: [
                  {
                    readWriteType: 'All',
                    includeManagementEvents: true,
                  },
                ],
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_21 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when a trail has set IsMultiRegionTrail is set to false', async () => {
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            cloudtrail: [
              {
                isMultiRegionTrail: 'No',
                status: {
                  isLogging: true,
                },
                eventSelectors: [
                  {
                    readWriteType: 'All',
                    includeManagementEvents: true,
                  },
                ],
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_21 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when a trail has set isLogging is set to false', async () => {
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            cloudtrail: [
              {
                isMultiRegionTrail: 'Yes',
                status: {
                  isLogging: false,
                },
                eventSelectors: [
                  {
                    readWriteType: 'All',
                    includeManagementEvents: true,
                  },
                ],
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_21 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when a trail has set multi region as true with all read-write type and include management events false', async () => {
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            cloudtrail: [
              {
                isMultiRegionTrail: 'Yes',
                status: {
                  isLogging: true,
                },
                eventSelectors: [
                  {
                    readWriteType: 'All',
                    includeManagementEvents: false,
                  },
                ],
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_21 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when there not are any trail', async () => {
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            cloudtrail: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_21 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('AWS CIS 2.2 Ensure CloudTrail log file validation is enabled', () => {
    test('Should pass when a trail has log file validation enabled', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            logFileValidationEnabled: 'Yes',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_22 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when a trail has log file validation disabled', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            logFileValidationEnabled: 'No',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_22 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('AWS CIS 2.3 Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible', () => {
    test('Should pass when a policy contains a statement having an Effect set to Allow and a Principal not set to "*" or {"AWS" : "*"}', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            s3: [
              {
                bucketPolicies: [
                  {
                    policy: {
                      statement: [
                        {
                          effect: 'Allow',
                          principal: [
                            {
                              key: 'Service',
                              value: ['cloudtrail.amazonaws.com'],
                            },
                          ],
                        },
                      ],
                    },
                  },
                ],
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_23 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when a policy contains a statement having an Effect set to Allow and a Principal set to "*"', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            s3: [
              {
                bucketPolicies: [
                  {
                    policy: {
                      statement: [
                        {
                          effect: 'Allow',
                          principal: [
                            {
                              key: '',
                              value: ['*'],
                            },
                          ],
                        },
                      ],
                    },
                  },
                ],
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_23 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when a policy contains a statement having an Effect set to Allow and a Principal set to {"AWS" : "*"}', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            s3: [
              {
                bucketPolicies: [
                  {
                    policy: {
                      statement: [
                        {
                          effect: 'Allow',
                          principal: [
                            {
                              key: 'AWS',
                              value: ['*'],
                            },
                          ],
                        },
                      ],
                    },
                  },
                ],
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_23 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('AWS CIS 2.4 Ensure CloudTrail trails are integrated with CloudWatch Logs', () => {
    test('Should pass when a trail has cloudwatch logs integrated with a delivery date no more than a day', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            cloudWatchLogsLogGroupArn: cuid(),
            status: {
              latestCloudWatchLogsDeliveryTime: new Date().toISOString(),
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_24 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when a trail has cloudwatch logs integrated with a delivery date more than a day', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            cloudWatchLogsLogGroupArn: cuid(),
            status: {
              latestCloudWatchLogsDeliveryTime: '2021-11-20T16:18:21.724Z',
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_24 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
    test('Should fail when a trail does not have cloudwatch logs integrated', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            cloudWatchLogsLogGroupArn: null,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_24 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('AWS CIS 2.5 Ensure AWS Config is enabled in all regions', () => {
    test('Should pass when a configuration recorder is enabled in all regions', async () => {
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            configurationRecorders: [
              {
                recordingGroup: {
                  allSupported: true,
                  includeGlobalResourceTypes: true,
                },
                status: {
                  recording: true,
                  lastStatus: 'SUCCESS',
                },
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_25 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when a configuration recorder has recordingGroup object includes "allSupported": false', async () => {
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            configurationRecorders: [
              {
                recordingGroup: {
                  allSupported: false,
                  includeGlobalResourceTypes: true,
                },
                status: {
                  recording: true,
                  lastStatus: 'SUCCESS',
                },
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_25 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when a configuration recorder has recordingGroup object includes "includeGlobalResourceTypes": false', async () => {
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            configurationRecorders: [
              {
                recordingGroup: {
                  allSupported: true,
                  includeGlobalResourceTypes: false,
                },
                status: {
                  recording: true,
                  lastStatus: 'SUCCESS',
                },
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_25 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when a configuration recorder has status object includes "recording": false', async () => {
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            configurationRecorders: [
              {
                recordingGroup: {
                  allSupported: true,
                  includeGlobalResourceTypes: true,
                },
                status: {
                  recording: false,
                  lastStatus: 'SUCCESS',
                },
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_25 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when a configuration recorder has status object includes "lastStatus" not "SUCCESS"', async () => {
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            configurationRecorders: [
              {
                recordingGroup: {
                  allSupported: true,
                  includeGlobalResourceTypes: true,
                },
                status: {
                  recording: true,
                  lastStatus: 'FAILED',
                },
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_25 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when there not are any configurationRecorder', async () => {
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            configurationRecorders: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_25 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('AWS CIS 2.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket', () => {
    test("Should pass when a trail's bucket has access logging enabled", async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            s3: [
              {
                logging: 'Enabled',
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_26 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test("Should fail when a trail's bucket has access logging disabled", async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            s3: [
              {
                logging: 'Disabled',
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_26 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('AWS CIS 2.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs', () => {
    test('Should pass when cloudtrail logs are encrypted using a KMS key', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            kmsKeyId: cuid(),
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_27 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when cloudtrail logs are not encrypted', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            kmsKeyId: null,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_27 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('AWS CIS 2.8 Ensure rotation for customer created CMKs is enabled (Scored)', () => {
    test('Should pass when rotation is enabled with customer as a manager', async () => {
      const data = {
        queryawsKms: [
          {
            id: cuid(),
            keyManager: 'CUSTOMER',
            keyRotationEnabled: true,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_28 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass when rotation is enabled with AWS as a manager', async () => {
      const data = {
        queryawsKms: [
          {
            id: cuid(),
            keyManager: 'AWS',
            keyRotationEnabled: true,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_28 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when rotation is disabled with customer as a manager', async () => {
      const data = {
        queryawsKms: [
          {
            id: cuid(),
            keyManager: 'CUSTOMER',
            keyRotationEnabled: false,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_28 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when rotation is disabled with AWS as a manager', async () => {
      const data = {
        queryawsKms: [
          {
            id: cuid(),
            keyManager: 'AWS',
            keyRotationEnabled: false,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_28 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('AWS CIS 2.9 Ensure VPC flow logging is enabled in all VPCs (Scored)', () => {
    test('Should pass when flow logging is enabled for each VPC', async () => {
      const data = {
        queryawsVpc: [
          {
            id: cuid(),
            flowLogs: [
              {
                resourceId: cuid(),
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_29 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when flow logging is disabled on one VPC', async () => {
      const data = {
        queryawsVpc: [
          {
            id: cuid(),
            flowLogs: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_CIS_120_29 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })
})
