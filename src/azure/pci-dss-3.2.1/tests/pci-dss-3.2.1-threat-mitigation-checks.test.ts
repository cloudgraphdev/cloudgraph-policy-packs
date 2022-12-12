import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Azure_PCI_DSS_321_Threat_Mitigation_1 from '../rules/pci-dss-3.2.1-threat-mitigation-check-1'

export interface WebApplicationFirewallConfiguration {
  enabled: boolean | undefined
}

export interface QueryazureApplicationGateway {
  id: string
  webApplicationFirewallConfiguration: WebApplicationFirewallConfiguration
}

export interface PCIQueryResponse {
  queryazureApplicationGateway?: QueryazureApplicationGateway[]
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'PCI')
  })

  describe('Threat Mitigation Check 1: Ensure Azure Application Gateway Web application firewall (WAF) is enabled', () => {
    const testRule = async (
      enabled: boolean | undefined,
      expectedResult: Result,
    ): Promise<void> => {
      // Arrange
      const data: PCIQueryResponse = {
        queryazureApplicationGateway: [
          {
            id: cuid(),
            webApplicationFirewallConfiguration: {
              enabled,
            }
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Threat_Mitigation_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when the WAF is enabled', async () => {
      await testRule(true, Result.PASS)
    })
    test('Security Issue when the WAF is disabled', async () => {
      await testRule(false, Result.FAIL)
    })
    test('Security Issue when the WAF is not set', async () => {
      await testRule(undefined, Result.FAIL)
    })
  })
});
