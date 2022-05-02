import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_Cloudtrail_1 from '../rules/pci-dss-3.2.1-cloudtrail-check-1'
import Aws_PCI_DSS_321_Cloudtrail_2 from '../rules/pci-dss-3.2.1-cloudtrail-check-2'
import Aws_PCI_DSS_321_Cloudtrail_3 from '../rules/pci-dss-3.2.1-cloudtrail-check-3'
import Aws_PCI_DSS_321_Cloudtrail_4 from '../rules/pci-dss-3.2.1-cloudtrail-check-4'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'PCI',
    })
  })

  describe('CloudTrail Check 1: CloudTrail logs should be encrypted at rest using AWS KMS keys', () => {
    test('Should fail when it does not have a KMS configured for encryption', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            kmsKeyId: null,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Cloudtrail_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when it has a KMS key assigned for encryption', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            kmsKeyId: 'keyId',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Cloudtrail_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('CloudTrail Check 2: CloudTrail should be enabled', () => {
    test('Should fail when the Trail is not multi-region', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            isMultiRegionTrail: 'No',
            eventSelectors: [
              {
                readWriteType: 'All',
                includeManagementEvents: true,
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Cloudtrail_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when the Trail is multi-region but the event selectors are not configured correctly', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            isMultiRegionTrail: 'Yes',
            eventSelectors: [
              {
                readWriteType: 'ReadOnly',
                includeManagementEvents: false,
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Cloudtrail_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when the Trail is multi-region and the event selectors are configured correctly', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            isMultiRegionTrail: 'Yes',
            eventSelectors: [
              {
                readWriteType: 'All',
                includeManagementEvents: true,
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Cloudtrail_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('CloudTrail Check 3: CloudTrail log file validation should be enabled ', () => {
    test('Should fail when the log file validation is disabled', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            logFileValidationEnabled: 'No',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Cloudtrail_3 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when the log file validation is enabled', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            logFileValidationEnabled: 'Yes',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Cloudtrail_3 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('CloudTrail Check 4: CloudTrail trails should be integrated with CloudWatch Logs', () => {
    test('Should fail when the integration with CloudWatch Logs is disabled', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            cloudWatchLogsRoleArn: cuid(),
            status: {
              latestCloudWatchLogsDeliveryTime: '2021-11-20T16:18:21.724Z',
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Cloudtrail_4 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when the integration with CloudWatch Logs is enabled', async () => {
      const data = {
        queryawsCloudtrail: [
          {
            id: cuid(),
            cloudWatchLogsRoleArn: cuid(),
            status: {
              latestCloudWatchLogsDeliveryTime: new Date().toISOString(),
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Cloudtrail_4 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })
})
