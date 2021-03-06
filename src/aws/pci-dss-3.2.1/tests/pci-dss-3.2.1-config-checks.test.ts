import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_Config_1 from '../rules/pci-dss-3.2.1-config-check-1'
import { initRuleEngine } from '../../../utils/test'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'PCI')
  })

  describe('Config Check 1: AWS Config should be enabled', () => {
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
        Aws_PCI_DSS_321_Config_1 as Rule,
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
        Aws_PCI_DSS_321_Config_1 as Rule,
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
        Aws_PCI_DSS_321_Config_1 as Rule,
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
        Aws_PCI_DSS_321_Config_1 as Rule,
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
        Aws_PCI_DSS_321_Config_1 as Rule,
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
        Aws_PCI_DSS_321_Config_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })
})
