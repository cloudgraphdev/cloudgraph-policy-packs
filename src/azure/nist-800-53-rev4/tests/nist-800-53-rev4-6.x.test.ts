
/* eslint-disable max-len */
import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Azure_NIST_800_53_61 from '../rules/azure-nist-800-53-rev4-6.1'
import Azure_NIST_800_53_62 from '../rules/azure-nist-800-53-rev4-6.2'
import Azure_NIST_800_53_63 from '../rules/azure-nist-800-53-rev4-6.3'
import Azure_NIST_800_53_64 from '../rules/azure-nist-800-53-rev4-6.4'
import { initRuleEngine } from '../../../utils/test'

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

export interface NIST5xAppServiceWebAppQueryResponse {
  queryazureAppServiceWebApp?: QueryazureAppServiceWebApp[]
  queryazureResourceGroup?: QueryazureResourceGroup[]
}

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
  storageContainerPath?: string
}

export interface ServerBlobAuditingPolicy {
  retentionDays?: number
  state?: string
}

export interface QueryazureSqlServer {
  id: string
  adAdministrators?: ADAdministrators[]
  encryptionProtectors?: EncryptionProtectors[]
  serverSecurityAlertPolicies?: ServerSecurityAlertPolicy[]
  vulnerabilityAssessments?: ServerVulnerabilityAssessment[]
  serverBlobAuditingPolicies?: ServerBlobAuditingPolicy[]
}

export interface Configuration {
  name?: string
  value?: string
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

export interface DatabaseSqlLogicalDatabaseTransparentDataEncryption {
  state?: string
}

export interface QueryazureDatabaseSql {
  id: string
  transparentDataEncryptions?: DatabaseSqlLogicalDatabaseTransparentDataEncryption[]
}

export interface QueryazurePostgreSqlServer {
  id: string
  configurations?: PostgreSqlServerConfiguration[]
  firewallRules?: PostgreSqlServerFirewallRules[]
  sslEnforcement?: string
}

export interface QueryazureMySqlServer {
  id: string
  sslEnforcement?: string
}

export interface NIST5xQueryResponse {
  queryazureSqlServer?: QueryazureSqlServer[]
  queryazurePostgreSqlServer?: QueryazurePostgreSqlServer[]
  queryazureDatabaseSql?: QueryazureDatabaseSql[]
  queryazureMySqlServer?: QueryazureMySqlServer[]
}

export interface Logging {
  read: boolean
  write: boolean
  delete: boolean
}

export interface QueueServiceProperties {
  logging: Logging
}
export interface BlobServiceProperties {
  deleteRetentionPolicyEnabled: boolean
  deleteRetentionPolicyDays: number | null
}

export interface QueryazureStorageAccount {
  id: string
  enableHttpsTrafficOnly?: string
  allowBlobPublicAccess?: string
  networkRuleSetDefaultAction?: string
  encryptionKeySource?: string
  blobServiceProperties?: BlobServiceProperties
  queueServiceProperties?: QueueServiceProperties
}

export interface NIST5xStorageAccountQueryResponse {
  queryazureStorageAccount?: QueryazureStorageAccount[]
}

describe('Azure NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('azure', 'NIST')
  })

  describe('Azure CIS 9.2 Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service', () => {
    const getTestRuleFixture = (httpsOnly: boolean): NIST5xAppServiceWebAppQueryResponse => {
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
      data: NIST5xAppServiceWebAppQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_61 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a httpsOnly set to On', async () => {
      const data: NIST5xAppServiceWebAppQueryResponse = getTestRuleFixture(true)

      await testRule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a httpsOnly set to Off', async () => {
      const data: NIST5xAppServiceWebAppQueryResponse = getTestRuleFixture(false)

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 6.2 Ensure \'Enforce SSL connection\' is set to \'ENABLED\' for MySQL Database Server', () => {
    const getTestRuleFixture = (
      sslEnforcement?: string | undefined
    ): NIST5xQueryResponse => {
      return {
        queryazureMySqlServer: [
          {
            id: cuid(),
            sslEnforcement,
          },
        ],
      }
    }

    const testRule = async (
      data: NIST5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_62 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when \'Enforce SSL connection\' is set to \'ENABLED\' for MySQL Database Server', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Enabled')

      await testRule(data, Result.PASS)
    })

    test('Security Security Issue when \'Enforce SSL connection\' for MySQL Database Server is not configured', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture()

      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 6.3 Ensure \'Enforce SSL connection\' is set to \'ENABLED\' for PostgreSQL Database Server', () => {
    const getTestRuleFixture = (
      sslEnforcement?: string | undefined
    ): NIST5xQueryResponse => {
      return {
        queryazurePostgreSqlServer: [
          {
            id: cuid(),
            sslEnforcement,
          },
        ],
      }
    }

    const testRule = async (
      data: NIST5xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_63 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when \'Enforce SSL connection\' is set to \'ENABLED\' for PostgreSQL Database Server', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture('Enabled')
      await testRule(data, Result.PASS)
    })

    test('Security Security Issue when \'Enforce SSL connection\' for PostgreSQL Database Server is not configured', async () => {
      const data: NIST5xQueryResponse = getTestRuleFixture()
      await testRule(data, Result.FAIL)
    })
  })

  describe('Azure NIST 6.4 Ensure that "Secure transfer required" is set to "Enabled"', () => {
    const getTestRuleFixture = (
      enableHttpsTrafficOnly: string
    ): NIST5xStorageAccountQueryResponse => {
      return {
        queryazureStorageAccount: [
          {
            id: cuid(),
            enableHttpsTrafficOnly
          },
        ],
      }
    }

    const testRule = async (
      data: NIST5xStorageAccountQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Azure_NIST_800_53_64 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when Storage Accounts has "Secure transfer required" set to "Enabled"', async () => {
      const data: NIST5xStorageAccountQueryResponse = getTestRuleFixture('Yes')

      await testRule(data, Result.PASS)
    })


    test('Security Issue when Storage Accounts has "Secure transfer required" set to "Disabled"', async () => {
      const data: NIST5xStorageAccountQueryResponse = getTestRuleFixture('No')

      await testRule(data, Result.FAIL)
    })
  })
})
