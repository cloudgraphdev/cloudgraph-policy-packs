/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Gcp_CIS_120_48 from '../rules/gcp-cis-1.2.0-4.8'
import Gcp_CIS_120_49 from '../rules/gcp-cis-1.2.0-4.9'
import Gcp_CIS_120_411 from '../rules/gcp-cis-1.2.0-4.11'

export interface AccessConfigs {
  natIP: string | null
}

export interface NetworkInterfaces {
  accessConfigs: AccessConfigs[]
}

export interface ShieldedInstanceConfig {
  enableIntegrityMonitoring: boolean
  enableVtpm: boolean
}

export interface ConfidentialInstanceConfig {
  enableConfidentialCompute: boolean
}

export interface QuerygcpVmInstance {
  id: string
  name?: string
  shieldedInstanceConfig?: ShieldedInstanceConfig
  confidentialInstanceConfig?: ConfidentialInstanceConfig
  networkInterfaces?: NetworkInterfaces[]
}
export interface CIS4xQueryResponse {
  querygcpVmInstance?: QuerygcpVmInstance[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine('gcp', 'CIS')
  })
  describe('GCP CIS 4.8 Ensure Compute instances are launched with Shielded VM enabled', () => {
    const test48Rule = async (
      enableIntegrityMonitoring: boolean,
      enableVtpm: boolean,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS4xQueryResponse = {
        querygcpVmInstance: [
          {
            id: cuid(),
            shieldedInstanceConfig: {
              enableIntegrityMonitoring,
              enableVtpm,
            },
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_48 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a shieldedInstanceConfig with enableIntegrityMonitoring and enableVtpm enabled', async () => {
      await test48Rule(true, true, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a shieldedInstanceConfig with enableIntegrityMonitoring and enableVtpm disabled', async () => {
      await test48Rule(false, false, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with a shieldedInstanceConfig with enableIntegrityMonitoring enabled and enableVtpm disabled', async () => {
      await test48Rule(true, false, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with a shieldedInstanceConfig with enableIntegrityMonitoring disabled and enableVtpm enabled', async () => {
      await test48Rule(false, true, Result.FAIL)
    })
  })

  describe('GCP CIS 4.9 Ensure that Compute instances do not have public IP addresses', () => {
    const test49Rule = async (
      instanceName: string,
      natIP: string | null,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS4xQueryResponse = {
        querygcpVmInstance: [
          {
            id: cuid(),
            name: instanceName,
            networkInterfaces: [
              {
                accessConfigs: [
                  {
                    natIP
                  },
                ],
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_49 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with an instance cretaed by GKE with natIP', async () => {
      await test49Rule('gke-instance-1', '34.69.30.133', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with an instance cretaed by GKE without natIp', async () => {
      await test49Rule('gke-instance-1', '34.69.30.133', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random instance without natIP', async () => {
      await test49Rule('instance-1', null, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a random instance with natIP', async () => {
      await test49Rule('instance-1', '34.69.30.133', Result.FAIL)
    })
  })

  describe('GCP CIS 4.11 Ensure Compute instances are launched with Shielded VM enabled', () => {
    const test411Rule = async (
      enableConfidentialCompute: boolean,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS4xQueryResponse = {
        querygcpVmInstance: [
          {
            id: cuid(),
            confidentialInstanceConfig: {
              enableConfidentialCompute
            },
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_411 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a confidentialInstanceConfig with enableConfidentialCompute enabled', async () => {
      await test411Rule(true, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a confidentialInstanceConfig with enableConfidentialCompute disabled', async () => {
      await test411Rule(false, Result.FAIL)
    })
  })
})
