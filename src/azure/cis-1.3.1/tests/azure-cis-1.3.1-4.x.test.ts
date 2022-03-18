/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_CIS_131_421 from '../rules/azure-cis-1.3.1-4.2.1'
import Azure_CIS_131_422 from '../rules/azure-cis-1.3.1-4.2.2'
import Azure_CIS_131_423 from '../rules/azure-cis-1.3.1-4.2.3'
import Azure_CIS_131_424 from '../rules/azure-cis-1.3.1-4.2.4'
import Azure_CIS_131_425 from '../rules/azure-cis-1.3.1-4.2.5'
import Azure_CIS_131_435 from '../rules/azure-cis-1.3.1-4.3.5'
import Azure_CIS_131_436 from '../rules/azure-cis-1.3.1-4.3.6'
import Azure_CIS_131_437 from '../rules/azure-cis-1.3.1-4.3.7'
import Azure_CIS_131_438 from '../rules/azure-cis-1.3.1-4.3.8'
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

export interface ServerVulnerabilityAssessmentRecurringScansProperties {
  emails?: string[]
  emailSubscriptionAdmins?: boolean
  isEnabled?: boolean
}
export interface ServerVulnerabilityAssessment {
  recurringScans?: ServerVulnerabilityAssessmentRecurringScansProperties
}

export interface QueryazureSqlServer {
  id: string
  adAdministrators?: ADAdministrators[]
  encryptionProtectors?: EncryptionProtectors[]
  serverSecurityAlertPolicies?: ServerSecurityAlertPolicy[]
  vulnerabilityAssessments?: ServerVulnerabilityAssessment[]
}

export interface PostgreSqlServerConfiguration {
  name: string
  value: string | number
}

export interface PostgreSqlServerFirewallRules {
  name: string
  startIpAddress: string
  endIpAddress: string
}

export interface QueryazurePostgreSqlServer {
  id: string
  configurations?: PostgreSqlServerConfiguration[]
  firewallRules?: PostgreSqlServerFirewallRules[]
}

export interface CIS4xQueryResponse {
  queryazureSqlServer?: QueryazureSqlServer[]
  queryazurePostgreSqlServer?: QueryazurePostgreSqlServer[]
}

describe('CIS Microsoft Azure Foundations: 1.3.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'azure',
      entityName: 'CIS',
    })
  })

  describe("Azure CIS 4.2.1 Ensure that Advanced Threat Protection (ATP) on a SQL server is set to 'Enabled'", () => {
    const getTestRuleFixture = (
      state?: string | undefined
    ): CIS4xQueryResponse => {
      return {
        queryazureSqlServer: [
          {
            id: cuid(),
            serverSecurityAlertPolicies: state
              ? [
                  {
                    state,
                  },
                ]
              : [],
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

    test("No Security Issue when Advanced Threat Protection (ATP) on a SQL server is set to 'Enabled'", async () => {
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
            vulnerabilityAssessments: emailSubscriptionAdmins
              ? [
                  {
                    recurringScans: {
                      emailSubscriptionAdmins,
                    },
                  },
                ]
              : [],
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
            vulnerabilityAssessments: isEnabled
              ? [
                  {
                    recurringScans: {
                      isEnabled,
                    },
                  },
                ]
              : [],
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
            vulnerabilityAssessments: emails
              ? [
                  {
                    recurringScans: {
                      emails,
                    },
                  },
                ]
              : [],
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

  describe("Azure CIS 4.2.5 Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server", () => {
    const getTestRuleFixture = (
      emailSubscriptionAdmins?: boolean | undefined
    ): CIS4xQueryResponse => {
      return {
        queryazureSqlServer: [
          {
            id: cuid(),
            vulnerabilityAssessments: emailSubscriptionAdmins
              ? [
                  {
                    recurringScans: {
                      emailSubscriptionAdmins,
                    },
                  },
                ]
              : [],
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

    test("No Security Issue when VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server", async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture(true)

      await testRule(data, Result.PASS)
    })

    test("Security Security Issue when VA setting 'Also send email notifications to admins and subscription owners' for a SQL server is not configured", async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture()

      await testRule(data, Result.FAIL)
    })
  })

  describe("4.3.5 Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server", () => {
    const getTestRuleFixture = (
      logDisconnections?: string | undefined
    ): CIS4xQueryResponse => {
      return {
        queryazurePostgreSqlServer: [
          {
            id: cuid(),
            configurations: logDisconnections
              ? [
                  {
                    name: 'log_disconnections',
                    value: logDisconnections,
                  },
                ]
              : [],
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
        Azure_CIS_131_435 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when log_disconnections is set to 'on' for PostgreSQL Database Server", async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture('on')

      await testRule(data, Result.PASS)
    })

    test("Security Security Issue when log_disconnections is set to 'off' for PostgreSQL Database Server", async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture('off')

      await testRule(data, Result.FAIL)
    })
  })

  describe("Azure CIS 4.3.6 Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server", () => {
    const getTestRuleFixture = (
      connectionThrottling?: string | undefined
    ): CIS4xQueryResponse => {
      return {
        queryazurePostgreSqlServer: [
          {
            id: cuid(),
            configurations: connectionThrottling
              ? [
                  {
                    name: 'connection_throttling',
                    value: connectionThrottling,
                  },
                ]
              : [],
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
        Azure_CIS_131_436 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when connection_throttling is set to 'on' for PostgreSQL Database Server", async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture('on')

      await testRule(data, Result.PASS)
    })

    test("Security Security Issue when connection_throttling is set to 'off' for PostgreSQL Database Server", async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture('off')

      await testRule(data, Result.FAIL)
    })
  })

  describe("Azure CIS 4.3.7 Ensure server parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server", () => {
    const getTestRuleFixture = (
      days?: string | number | undefined
    ): CIS4xQueryResponse => {
      return {
        queryazurePostgreSqlServer: [
          {
            id: cuid(),
            configurations: days
              ? [
                  { name: 'test_name', value: 4 },
                  {
                    name: 'log_retention_days',
                    value: days,
                  },
                ]
              : [],
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
        Azure_CIS_131_437 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when 'log_retention_days' is greater than 3 days for PostgreSQL Database Server", async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture(4)

      await testRule(data, Result.PASS)
    })

    test("Security Security Issue when 'log_retention_days' is less or equal than 3 days for PostgreSQL Database Server", async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture(2)

      await testRule(data, Result.FAIL)
    })
  })

  describe("Azure CIS Azure CIS 4.3.8 Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled", () => {
    const getTestRuleFixture = (
      name: string,
      startIpAddress: string,
      endIpAddress: string
    ): CIS4xQueryResponse => {
      return {
        queryazurePostgreSqlServer: [
          {
            id: cuid(),
            firewallRules: [
              {
                name,
                startIpAddress,
                endIpAddress,
              },
            ],
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
        Azure_CIS_131_438 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when 'Allow access to Azure services' for PostgreSQL Database Server is disabled", async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture(
        'whatever',
        '0.0.0.1',
        '0.1.0.0'
      )

      await testRule(data, Result.PASS)
    })

    test("Security Issue when 'Allow access to Azure services' for PostgreSQL Database Server is enabled by address", async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture(
        'whateverRule',
        '0.0.0.0',
        '0.0.0.0'
      )

      await testRule(data, Result.FAIL)
    })

    test("Security Issue when 'Allow access to Azure services' for PostgreSQL Database Server is enabled", async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture(
        'AllowAllAzureIps',
        '0.1.0.0',
        '0.0.0.1'
      )

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
            adAdministrators: adminId
              ? [
                  {
                    id: adminId,
                  },
                ]
              : [],
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
      uri?: string | null
    ): CIS4xQueryResponse => {
      return {
        queryazureSqlServer: [
          {
            id: cuid(),
            encryptionProtectors: [
              {
                kind,
                serverKeyType,
                uri,
              },
            ],
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
      const data: CIS4xQueryResponse = getTestRuleFixture(
        'azurekeyvault',
        'AzureKeyVault',
        'https://aws.amazon.com/sqlservers/'
      )

      await testRule(data, Result.PASS)
    })

    test('Security Issue when SQL servers TDE protector has kind and serverKeyType not equal to azurekeyvault', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture(
        'servicemanaged',
        'ServiceManaged',
        'https://aws.amazon.com/sqlservers/'
      )

      await testRule(data, Result.FAIL)
    })

    test('Security Issue when SQL servers TDE protector has a uri null', async () => {
      const data: CIS4xQueryResponse = getTestRuleFixture(
        'azurekeyvault',
        'AzureKeyVault',
        null
      )

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
