import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_GuardDuty_1 from '../rules/pci-dss-3.2.1-guardDuty-check-1'
import { initRuleEngine } from '../../../utils/test'

interface GuardDutyData {
  region: string
  status: string
  dataSources: {
    cloudTrail: {
      status: string
    }
    dnsLogs: {
      status: string
    }
    flowLogs: {
      status: string
    }
    s3Logs: {
      status: string
    }
  }
}

const generateDetectors = (
  regions: string[],
  enabledGuardDuty = 'ENABLED',
  enabledDataSource = 'DISABLED'
): GuardDutyData[] =>
  regions.map((r: any) => ({
    region: r,
    status: enabledGuardDuty,
    dataSources: {
      cloudTrail: {
        status: enabledDataSource,
      },
      dnsLogs: {
        status: enabledDataSource,
      },
      flowLogs: {
        status: enabledDataSource,
      },
      s3Logs: {
        status: enabledDataSource,
      },
    },
  }))

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'PCI')
  })

  describe('GuardDuty Check 1: GuardDuty should be enabled', () => {
    test('Should fail when it does not have any detectors configured', async () => {
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            regions: ['us-east-2', 'us-east-1', 'us-west-2', 'us-west-1'],
            __typename: 'awsAccount',
            guardDutyDetectors: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_GuardDuty_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when it finds an unsupported region', async () => {
      const regions = ['ap-northeast-3']
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            regions,
            __typename: 'awsAccount',
            guardDutyDetectors: generateDetectors(regions),
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_GuardDuty_1 as Rule,
        {
          ...data,
        } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when it finds a DISABLED status', async () => {
      const enabledDetectors = generateDetectors(['us-east-1'])
      const disabledDetectors = generateDetectors(['us-east-2'], 'DISABLED')
      const regions = ['us-east-1', 'us-east-2']
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            regions,
            __typename: 'awsAccount',
            guardDutyDetectors: [...enabledDetectors, ...disabledDetectors],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_GuardDuty_1 as Rule,
        {
          ...data,
        } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when it finds a DataSource enabled status', async () => {
      const regions = ['us-east-1', 'us-east-2']
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            regions,
            __typename: 'awsAccount',
            guardDutyDetectors: generateDetectors(
              [...regions],
              'DISABLED',
              'ENABLED'
            ),
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_GuardDuty_1 as Rule,
        {
          ...data,
        } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when regions are scanned and configured with GuardDuty', async () => {
      const regions = ['us-east-2']
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            regions,
            __typename: 'awsAccount',
            guardDutyDetectors: generateDetectors(regions),
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_GuardDuty_1 as Rule,
        {
          ...data,
        } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when there are scanned region without GuardDuty detectors configured', async () => {
      const configuredRegions = ['us-east-2', 'us-east-1']
      const data = {
        queryawsAccount: [
          {
            id: cuid(),
            regions: [...configuredRegions, 'us-west-1', 'us-west-2'],
            __typename: 'awsAccount',
            guardDutyDetectors: generateDetectors(configuredRegions),
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_GuardDuty_1 as Rule,
        {
          ...data,
        } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })
})
