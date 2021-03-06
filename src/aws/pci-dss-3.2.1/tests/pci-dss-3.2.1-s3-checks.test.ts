import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_S3_1 from '../rules/pci-dss-3.2.1-s3-check-1'
import Aws_PCI_DSS_321_S3_2 from '../rules/pci-dss-3.2.1-s3-check-2'
import Aws_PCI_DSS_321_S3_3 from '../rules/pci-dss-3.2.1-s3-check-3'
import Aws_PCI_DSS_321_S3_4 from '../rules/pci-dss-3.2.1-s3-check-4'
import Aws_PCI_DSS_321_S3_5 from '../rules/pci-dss-3.2.1-s3-check-5'
import Aws_PCI_DSS_321_S3_6 from '../rules/pci-dss-3.2.1-s3-check-6'
import { initRuleEngine } from '../../../utils/test'

const allowAll = {
  action: ['*'],
  effect: 'Allow',
  principal: [
    {
      key: 'AWS',
      value: ['*', 'arn:aws:iam::12345:root'],
    },
  ],
}

const allowPublicWriteAccess = [
  {
    action: ['s3:DeleteObject'],
    effect: 'Allow',
    principal: [
      {
        key: 'AWS',
        value: ['*'],
      },
    ],
  },
  {
    action: ['s3:PutObject'],
    effect: 'Allow',
    principal: [
      {
        key: 'AWS',
        value: ['*'],
      },
    ],
  },
]

const allowPublicReadAccess = [
  {
    action: ['s3:GetObject'],
    effect: 'Allow',
    principal: [
      {
        key: 'AWS',
        value: ['*'],
      },
    ],
  },
  {
    action: ['s3:GetObjectVersion'],
    effect: 'Allow',
    principal: [
      {
        key: 'AWS',
        value: ['*'],
      },
    ],
  },
  {
    action: ['s3:ListBucket'],
    effect: 'Allow',
    principal: [
      {
        key: 'AWS',
        value: ['*'],
      },
    ],
  },
  {
    action: ['s3:ListBucketVersions'],
    effect: 'Allow',
    principal: [
      {
        key: 'AWS',
        value: ['*'],
      },
    ],
  },
]

const allowSSLRequestsOnly = {
  condition: [
    {
      key: 'aws:SecureTransport',
      value: ['false'],
    },
  ],
  action: ['s3:*'],
  effect: 'Deny',
  principal: [
    {
      key: 'AWS',
      value: ['*'],
    },
  ],
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'PCI')
  })
  describe('S3 Check 1: S3 buckets should prohibit public write access', () => {
    test('Should fail when it has blockPublicPolicy and blockPublicAcls disabled', async () => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            __typename: 'awsS3',
            blockPublicPolicy: 'No',
            blockPublicAcls: 'No',
            policy: null,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when it has a policy with public write access', async () => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            __typename: 'awsS3',
            blockPublicPolicy: 'Yes',
            blockPublicAcls: 'Yes',
            policy: {
              statement: [allowAll, ...allowPublicWriteAccess],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when it has a policy with public read access', async () => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            __typename: 'awsS3',
            blockPublicPolicy: 'Yes',
            blockPublicAcls: 'Yes',
            policy: {
              statement: [...allowPublicReadAccess],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass when it has blockPublicPolicy and blockPublicAcls enabled', async () => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            __typename: 'awsS3',
            blockPublicPolicy: 'Yes',
            blockPublicAcls: 'Yes',
            policy: null,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('S3 Check 2: S3 buckets should prohibit public read access', () => {
    test('Should fail when it has blockPublicPolicy and blockPublicAcls disabled', async () => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            __typename: 'awsS3',
            blockPublicPolicy: 'No',
            blockPublicAcls: 'No',
            bucketPolicies: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when it has a policy with public read access', async () => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            __typename: 'awsS3',
            blockPublicPolicy: 'Yes',
            blockPublicAcls: 'Yes',
            policy: {
              statement: [allowAll, ...allowPublicReadAccess],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when it has a policy with public write access', async () => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            __typename: 'awsS3',
            blockPublicPolicy: 'Yes',
            blockPublicAcls: 'Yes',
            bucketPolicies: [
              {
                policy: {
                  statement: [...allowPublicWriteAccess],
                },
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass when it has blockPublicPolicy and blockPublicAcls enabled', async () => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            __typename: 'awsS3',
            blockPublicPolicy: 'Yes',
            blockPublicAcls: 'Yes',
            policy: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
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

  describe('S3 Check 5: S3 buckets should require requests to use Secure Socket Layer', () => {
    test('Should pass when it does not have any policies configured', async () => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            __typename: 'awsS3',
            policy: null,
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_5 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when it has a policy that requires SSL connections only', async () => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            __typename: 'awsS3',
            policy: {
              statement: [allowSSLRequestsOnly],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_5 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when it has not a policy that requires SSL connections only', async () => {
      const data = {
        queryawsS3: [
          {
            id: cuid(),
            __typename: 'awsS3',
            policy: {
              statement: [allowAll],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_S3_5 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
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
