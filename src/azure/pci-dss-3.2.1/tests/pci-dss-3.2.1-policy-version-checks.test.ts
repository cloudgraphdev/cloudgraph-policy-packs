import { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'
import { initRuleEngine } from '../../../utils/test'

import Azure_PCI_DSS_321_Policy_Version_1 from '../rules/pci-dss-3.2.1-policy-version-check-1'

export interface SiteConfig {
  minTlsVersion?: string
  http20Enabled?: boolean
  ftpsState?: string
  managedServiceIdentityId?: number | null
}
export interface QueryazureAppServiceWebApp {
  id: string
  name?: string
  httpsOnly?: boolean
  siteConfig?: SiteConfig
  clientCertEnabled?: boolean
  authEnabled?: boolean
  identityPrincipalId?: string | null
}
export interface PCIQueryResponse {
  queryazureAppServiceWebApp?: QueryazureAppServiceWebApp[]
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'PCI')
  })

  describe('Azure CIS 9.3 Ensure web app is using the latest version of TLS encryption', () => {
    const getTestRuleFixture = (minTlsVersion: string): PCIQueryResponse => {
      return {
        queryazureAppServiceWebApp: [
          {
            id: cuid(),
            siteConfig: {
              minTlsVersion,
            },
          },
        ],
      }
    }

    const testRule = async (
      data: PCIQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_PCI_DSS_321_Policy_Version_1 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a siteConfig minTlsVersion equal to 1.2', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('1.2')

      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a siteConfig minTlsVersion not equal to 1.2', async () => {
      const data: PCIQueryResponse = getTestRuleFixture('1.1')

      await testRule(data, Result.FAIL)
    })
  })
  
})
