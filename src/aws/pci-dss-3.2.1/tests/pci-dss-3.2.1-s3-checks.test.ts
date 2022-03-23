import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_S3_3 from '../rules/pci-dss-3.2.1-s3-check-3'
import Aws_PCI_DSS_321_S3_4 from '../rules/pci-dss-3.2.1-s3-check-4'
import Aws_PCI_DSS_321_S3_6 from '../rules/pci-dss-3.2.1-s3-check-6'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'PCI',
    })
  })
  describe('S3 Check 3: S3 buckets should have cross-region replication enabled', () => {
    test('Should fail when cross-region replication is disabled', async () => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            crossRegionReplication: 'Disabled',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_3 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when cross-region replication is enabled', async () => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            crossRegionReplication: 'Enabled',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_3 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })
  describe('S3 Check 4: S3 buckets should have server-side encryption enabled', () => {
    test('Should fail when encryption is disabled', async () => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            encrypted: 'No',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_4 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when encryption is enabled', async () => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            encrypted: 'Yes',
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_4 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })
  describe('S3 Check 6: S3 Block Public Access setting should be enabled', () => {
    const testBlockPublicAcessSetting = async (
      {
        blockPublicAcls,
        blockPublicPolicy,
        ignorePublicAcls,
        restrictPublicBuckets,
      }: {
        blockPublicAcls: string
        blockPublicPolicy: string
        ignorePublicAcls: string
        restrictPublicBuckets: string
      },
      expected: Result
    ): Promise<void> => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            blockPublicAcls,
            blockPublicPolicy,
            ignorePublicAcls,
            restrictPublicBuckets,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_6 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(expected)
    }

    test('Should fail when blockPublicAcls is disabled', async () => {
      await testBlockPublicAcessSetting(
        {
          blockPublicAcls: 'No',
          blockPublicPolicy: 'Yes',
          ignorePublicAcls: 'Yes',
          restrictPublicBuckets: 'Yes',
        },
        Result.FAIL
      )
    })

    test('Should fail when blockPublicPolicy is disabled', async () => {
      await testBlockPublicAcessSetting(
        {
          blockPublicAcls: 'Yes',
          blockPublicPolicy: 'No',
          ignorePublicAcls: 'Yes',
          restrictPublicBuckets: 'Yes',
        },
        Result.FAIL
      )
    })

    test('Should fail when ignorePublicAcls is disabled', async () => {
      await testBlockPublicAcessSetting(
        {
          blockPublicAcls: 'No',
          blockPublicPolicy: 'No',
          ignorePublicAcls: 'Yes',
          restrictPublicBuckets: 'No',
        },
        Result.FAIL
      )
    })

    test('Should fail when restrictPublicBuckets is disabled', async () => {
      await testBlockPublicAcessSetting(
        {
          blockPublicAcls: 'No',
          blockPublicPolicy: 'No',
          ignorePublicAcls: 'No',
          restrictPublicBuckets: 'Yes',
        },
        Result.FAIL
      )
    })

    test('Should pass when all block public access settings are enabled', async () => {
      await testBlockPublicAcessSetting(
        {
          blockPublicAcls: 'Yes',
          blockPublicPolicy: 'Yes',
          ignorePublicAcls: 'Yes',
          restrictPublicBuckets: 'Yes',
        },
        Result.PASS
      )
    })
  })
})