import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_S3_6 from '../rules/pci-dss-3.2.1-s3-check-6'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'PCI',
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
