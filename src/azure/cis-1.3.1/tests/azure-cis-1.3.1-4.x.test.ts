/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_CIS_131_421 from '../rules/azure-cis-1.3.1-4.2.1'
import Azure_CIS_131_422 from '../rules/azure-cis-1.3.1-4.2.2'
import Azure_CIS_131_423 from '../rules/azure-cis-1.3.1-4.2.3'
import Azure_CIS_131_424 from '../rules/azure-cis-1.3.1-4.2.4'
import Azure_CIS_131_425 from '../rules/azure-cis-1.3.1-4.2.5'
import Azure_CIS_131_44 from '../rules/azure-cis-1.3.1-4.4'
import Azure_CIS_131_45 from '../rules/azure-cis-1.3.1-4.5'

export interface EncryptionProtectors {
  kind?: string | null
  serverKeyType?: string | null
  uri?: string | null
}

export interface ADAdministrators {
  id: string
}

export interface ServerSecurityAlertPolicy {
  state: string
}
export interface ServerVulnerabilityAssessment {
  recurringScans?: ServerVulnerabilityAssessmentRecurringScansProperties
}

export interface ServerVulnerabilityAssessmentRecurringScansProperties {
  emails?: string[]
  emailSubscriptionAdmins?: boolean
  isEnabled?: boolean
}

export interface QueryazureSqlServer {
  id: string
  adAdministrators?: ADAdministrators[]
  encryptionProtectors?: EncryptionProtectors[]
  serverSecurityAlertPolicies?: ServerSecurityAlertPolicy[]
  vulnerabilityAssessments?: ServerVulnerabilityAssessment[]
}

export interface CIS4xQueryResponse {
  queryazureSqlServer?: QueryazureSqlServer[]
}

describe('CIS Microsoft Azure Foundations: 1.3.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'azure', entityName: 'CIS'} )
  })

  describe('Azure CIS 4.2.1 Ensure that Advanced Threat Protection (ATP) on a SQL server is set to \'Enabled\'', () => {
    const getTestRuleFixture = (
      state?: string | undefined
    ): CIS4xQueryResponse => {
      return {
        queryazureSqlServer: [
          {
            id: cuid(),
            serverSecurityAlertPolicies: state ? [
              {
                state
              }
            ] : []
          },
        ],
      }
    }

    const testRule = async (
      data: CIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_421 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Advanced Threat Protection (ATP) on a SQL server is set to \'Enabled\'', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture('Enabled')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Advanced Threat Protection (ATP) on a SQL server is not configured', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture()

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 4.2.2 Ensure that Vulnerability Assessment (VA) is enabled on a SQL server by setting a Storage Account', () => {
    const getTestRuleFixture = (
      emailSubscriptionAdmins?: boolean | undefined
    ): CIS4xQueryResponse => {
      return {
        queryazureSqlServer: [
          {
            id: cuid(),
            vulnerabilityAssessments: emailSubscriptionAdmins ? [
              {
                recurringScans: {
                  emailSubscriptionAdmins,
                }
              }
            ] : []
          },
        ],
      }
    }

    const testRule = async (
      data: CIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_422 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Vulnerability Assessment (VA) is enabled on a SQL server by setting a Storage Account', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture(true)

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Vulnerability Assessment (VA) for the SQL server is not configured', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture()

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 4.2.3 Ensure that VA setting Periodic Recurring Scans is enabled on a SQL server', () => {
    const getTestRuleFixture = (
      isEnabled?: boolean | undefined
    ): CIS4xQueryResponse => {
      return {
        queryazureSqlServer: [
          {
            id: cuid(),
            vulnerabilityAssessments: isEnabled ? [
              {
                recurringScans: {
                  isEnabled,
                }
              }
            ] : []
          },
        ],
      }
    }

    const testRule = async (
      data: CIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_423 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when VA setting Periodic Recurring Scans is enabled on a SQL server', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture(true)

      await testRule(data, Result.PASS)
    })


    test('Security Issue when VA setting Periodic Recurring Scans is not configured', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture()

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 4.2.4 Ensure that VA setting Send scan reports to is configured for a SQL server', () => {
    const getTestRuleFixture = (
      emails?: string[] | undefined
    ): CIS4xQueryResponse => {
      return {
        queryazureSqlServer: [
          {
            id: cuid(),
            vulnerabilityAssessments: emails ? [
              {
                recurringScans: {
                  emails,
                }
              }
            ] : []
          },
        ],
      }
    }

    const testRule = async (
      data: CIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_424 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when VA setting Send scan reports to is configured for a SQL server', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture(['mail1@mail.com'])

      await testRule(data, Result.PASS)
    })


    test('Security Issue when VA setting Send scan reports to for a SQL server is not configured', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture()

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 4.2.5 Ensure that VA setting \'Also send email notifications to admins and subscription owners\' is set for a SQL server', () => {
    const getTestRuleFixture = (
      emailSubscriptionAdmins?: boolean | undefined
    ): CIS4xQueryResponse => {
      return {
        queryazureSqlServer: [
          {
            id: cuid(),
            vulnerabilityAssessments: emailSubscriptionAdmins ? [
              {
                recurringScans: {
                  emailSubscriptionAdmins,
                }
              }
            ] : []
          },
        ],
      }
    }

    const testRule = async (
      data: CIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_425 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when VA setting \'Also send email notifications to admins and subscription owners\' is set for a SQL server', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture(true)

      await testRule(data, Result.PASS)
    })


    test('Security Security Issue when VA setting \'Also send email notifications to admins and subscription owners\' for a SQL server is not configured', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture()

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 4.4 Ensure that Azure Active Directory Admin is configured', () => {
    const getTestRuleFixture = (
      adminId?: string | undefined
    ): CIS4xQueryResponse => {
      return {
        queryazureSqlServer: [
          {
            id: cuid(),
            adAdministrators: adminId ? [
              {
                id: adminId
              }
            ] : []
          },
        ],
      }
    }

    const testRule = async (
      data: CIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_44 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Azure Active Directory Admin is configured', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture(cuid())

      await testRule(data, Result.PASS)
    })


    test('Security Security Issue when Azure Active Directory Admin is not configured', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture()

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure CIS 4.5 Ensure SQL servers TDE protector is encrypted with Customer-managed key', () => {
    const getTestRuleFixture = (
      kind?: string | null,
      serverKeyType?: string | null,
      uri?: string | null,
    ): CIS4xQueryResponse => {
      return {
        queryazureSqlServer: [
          {
            id: cuid(),
            encryptionProtectors : [
              {
                kind,
                serverKeyType,
                uri
              }
            ]
          },
        ],
      }
    }

    const testRule = async (
      data: CIS4xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_CIS_131_45 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when SQL servers TDE protector is encrypted with Customer-managed key', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture('azurekeyvault', 'AzureKeyVault', 'https://aws.amazon.com/sqlservers/')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when SQL servers TDE protector has kind and serverKeyType not equal to azurekeyvault', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture('servicemanaged', 'ServiceManaged', 'https://aws.amazon.com/sqlservers/')

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when SQL servers TDE protector has a uri null', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture('azurekeyvault', 'AzureKeyVault', null)

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when SQL servers TDE protector is empty', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture()
      const sqlServer = data.queryazureSqlServer?.[0] as QueryazureSqlServer
      sqlServer.encryptionProtectors = []
      await testRule(data, Result.FAIL)
    })
  })
})