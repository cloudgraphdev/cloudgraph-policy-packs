/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_CIS_131_91 from '../rules/azure-cis-1.3.1-9.1'
import Azure_CIS_131_92 from '../rules/azure-cis-1.3.1-9.2'
import Azure_CIS_131_93 from '../rules/azure-cis-1.3.1-9.3'
import Azure_CIS_131_94 from '../rules/azure-cis-1.3.1-9.4'
import Azure_CIS_131_95 from '../rules/azure-cis-1.3.1-9.5'
import Azure_CIS_131_99 from '../rules/azure-cis-1.3.1-9.9'
import Azure_CIS_131_910 from '../rules/azure-cis-1.3.1-9.10'

export interface SiteConfig {
  minTlsVersion?: string
  http20Enabled?: boolean
  ftpsState?: string
  managedServiceIdentityId?: number | null
}
export interface AppServiceWebApps {
  siteConfig: SiteConfig
}
export interface QueryazureResourceGroup {
  id: string
  appServiceWebApps: AppServiceWebApps[]
  functionApps: AppServiceWebApps[]
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

export interface CIS9xQueryResponse {
  queryazureAppServiceWebApp?: QueryazureAppServiceWebApp[]
  queryazureResourceGroup?: QueryazureResourceGroup[]
}

describe('CIS Microsoft Azure Foundations: 1.3.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine('azure', 'CIS')
  })

  describe('Azure CIS 9.1 Ensure App Service Authentication is set on Azure App Service', () => {
    const getTestRuleFixture = (authEnabled: boolean): CIS9xQueryResponse => {
      return {
        queryazureAppServiceWebApp: [
          {
            id: cuid(),
            authEnabled,
          },
        ],
      }
    }

    const testRule = async (
      data: CIS9xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_91 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with Authentication set to On', async () => {
      const data: CIS9xQueryResponse = getTestRuleFixture(true)

      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with Authentication set to Off', async () => {
      const data: CIS9xQueryResponse = getTestRuleFixture(false)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 9.2 Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service', () => {
    const getTestRuleFixture = (httpsOnly: boolean): CIS9xQueryResponse => {
      return {
        queryazureAppServiceWebApp: [
          {
            id: cuid(),
            httpsOnly,
          },
        ],
      }
    }

    const testRule = async (
      data: CIS9xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_92 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a httpsOnly set to On', async () => {
      const data: CIS9xQueryResponse = getTestRuleFixture(true)

      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a httpsOnly set to Off', async () => {
      const data: CIS9xQueryResponse = getTestRuleFixture(false)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 9.3 Ensure web app is using the latest version of TLS encryption', () => {
    const getTestRuleFixture = (minTlsVersion: string): CIS9xQueryResponse => {
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
      data: CIS9xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_93 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a siteConfig minTlsVersion equal to 1.2', async () => {
      const data: CIS9xQueryResponse = getTestRuleFixture('1.2')

      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a siteConfig minTlsVersion not equal to 1.2', async () => {
      const data: CIS9xQueryResponse = getTestRuleFixture('1.1')

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 9.4 Ensure the web app has "Client Certificates (Incoming client certificates)" set to "On"', () => {
    const getTestRuleFixture = (
      clientCertEnabled: boolean
    ): CIS9xQueryResponse => {
      return {
        queryazureAppServiceWebApp: [
          {
            id: cuid(),
            clientCertEnabled,
          },
        ],
      }
    }

    const testRule = async (
      data: CIS9xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_94 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a clientCertEnabled set to true', async () => {
      const data: CIS9xQueryResponse = getTestRuleFixture(true)

      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a clientCertEnabled set to false', async () => {
      const data: CIS9xQueryResponse = getTestRuleFixture(false)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 9.5 Ensure that Register with Azure Active Directory is enabled on App Service', () => {
    const getTestRuleFixture = (
      webAppIdentityId?: number | null
      ): CIS9xQueryResponse => {
      return {
        queryazureAppServiceWebApp: [
          {
            id: cuid(),
            siteConfig: {
              managedServiceIdentityId: webAppIdentityId,
            },
          },
        ],
      }
    }

    const testRule = async (
      data: CIS9xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_95 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Web Apps has Identity enabled', async () => {
      const data: CIS9xQueryResponse = getTestRuleFixture(12345)

      await testRule(data, Result.PASS)
    })

    test('Security Issue when Web Apps has Identity disabled', async () => {
      const data: CIS9xQueryResponse = getTestRuleFixture(null)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 9.9 Ensure that "HTTP Version" is the latest, if used to run the web app', () => {
    const getTestRuleFixture = (http20Enabled: boolean): CIS9xQueryResponse => {
      return {
        queryazureAppServiceWebApp: [
          {
            id: cuid(),
            siteConfig: {
              http20Enabled,
            },
          },
        ],
      }
    }

    const testRule = async (
      data: CIS9xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_99 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a HTTP version 2.0 enabled', async () => {
      const data: CIS9xQueryResponse = getTestRuleFixture(true)

      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a HTTP version 2.0 not enabled', async () => {
      const data: CIS9xQueryResponse = getTestRuleFixture(false)

      await testRule(data, Result.FAIL)
    })
  })

  describe.skip('Azure CIS 9.10 Ensure FTP deployments are disabled', () => {
    const getTestRuleFixture = (
      webAppftpsState: string,
      functionAppftpsState: string
      ): CIS9xQueryResponse => {
      return {
        queryazureResourceGroup: [
          {
            id: cuid(),
            appServiceWebApps: [
              {
                siteConfig: {
                  ftpsState: webAppftpsState,
                },
              },
            ],
            functionApps: [
              {
                siteConfig: {
                  ftpsState: functionAppftpsState,
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS9xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_910 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Web Apps and Function Apps has FTP deployments state not set to "All allowed"', async () => {
      const data: CIS9xQueryResponse = getTestRuleFixture(
        'Disabled',
        'FtpsOnly'
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when Web Apps and Function Apps has FTP deployments state set to "All allowed"', async () => {
      const data: CIS9xQueryResponse = getTestRuleFixture(
        'AllAllowed',
        'AllAllowed'
      )

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when some Web Apps or Function Apps has FTP deployments state set to "All allowed"', async () => {
      const data: CIS9xQueryResponse = getTestRuleFixture(
        'FtpsOnly',
        'AllAllowed'
      )

      await testRule(data, Result.FAIL)
    })
  })
})
