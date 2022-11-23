/* eslint-disable max-len */
import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Gcp_CIS_130_612 from '../rules/gcp-cis-1.3.0-6.1.2'
import Gcp_CIS_130_613 from '../rules/gcp-cis-1.3.0-6.1.3'
import Gcp_CIS_130_621 from '../rules/gcp-cis-1.3.0-6.2.1'
import Gcp_CIS_130_622 from '../rules/gcp-cis-1.3.0-6.2.2'
import Gcp_CIS_130_623 from '../rules/gcp-cis-1.3.0-6.2.3'
import Gcp_CIS_130_624 from '../rules/gcp-cis-1.3.0-6.2.4'
import Gcp_CIS_130_625 from '../rules/gcp-cis-1.3.0-6.2.5'
import Gcp_CIS_130_626 from '../rules/gcp-cis-1.3.0-6.2.6'
import Gcp_CIS_130_627 from '../rules/gcp-cis-1.3.0-6.2.7'
import Gcp_CIS_130_628 from '../rules/gcp-cis-1.3.0-6.2.8'
import Gcp_CIS_130_631 from '../rules/gcp-cis-1.3.0-6.3.1'
import Gcp_CIS_130_632 from '../rules/gcp-cis-1.3.0-6.3.2'
import Gcp_CIS_130_633 from '../rules/gcp-cis-1.3.0-6.3.3'
import Gcp_CIS_130_634 from '../rules/gcp-cis-1.3.0-6.3.4'
import Gcp_CIS_130_635 from '../rules/gcp-cis-1.3.0-6.3.5'
import Gcp_CIS_130_636 from '../rules/gcp-cis-1.3.0-6.3.6'
import Gcp_CIS_130_637 from '../rules/gcp-cis-1.3.0-6.3.7'
import Gcp_CIS_130_64 from '../rules/gcp-cis-1.3.0-6.4'
import Gcp_CIS_130_65 from '../rules/gcp-cis-1.3.0-6.5'
import Gcp_CIS_130_66 from '../rules/gcp-cis-1.3.0-6.6'
import Gcp_CIS_130_67 from '../rules/gcp-cis-1.3.0-6.7'
import { initRuleEngine } from '../../../utils/test'

export interface DatabaseFlagsItem {
  name: string
  value: string | null
}

export interface AuthorizedNetwork {
  value: string
}

export interface IpConfiguration {
  requireSsl?: boolean | null
  authorizedNetworks?: AuthorizedNetwork[]
}

export interface BackupConfiguration {
  enabled: boolean | null
  startTime: string | null
}

export interface Settings {
  databaseFlags: DatabaseFlagsItem[]
  ipConfiguration?: IpConfiguration
  backupConfiguration?: BackupConfiguration
}

export interface IpAddress {
  type: string
}

export interface SqlInstances {
  id?: string
  name: string
  databaseVersion: string
  instanceType?: string
  backendType?: string
  settings: Settings
  ipAddresses?: IpAddress[]
}

export interface QuerygcpProject {
  id: string
  sqlInstances: SqlInstances[]
}

describe('CIS Google Cloud Platform Foundations: 1.3.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('gcp', 'CIS')
  })

  describe("GCP CIS 6.1.2 Ensure 'skip_show_database' database flag for Cloud SQL Mysql instance is set to 'on'", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'sql-i',
        name: 'test-mysql-instance',
        databaseVersion: 'MYSQL',
        settings: {
          databaseFlags: [
            {
              name: 'skip_show_database',
              value: 'on',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_612 as Rule,
        { querygcpSqlInstance: [data] }
      )
      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all MYSQL instances have the 'skip_show_database' set to 'on'", async () => {
      const data = {
        name: 'test-mysql-instance',
        id: 'db-id',
        databaseVersion: 'MYSQL',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'skip_show_database',
              value: 'on',
            },
          ],
        },
      }

      await testRule(data, Result.PASS)
    })

    test('Security Issue when the MYSQL instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the MYSQL instances do NOT have a 'skip_show_database' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'on',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the MYSQL instances do have a 'skip_show_database' database flag set to 'off'", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = 'off'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.1.3 Ensure that the 'local_infile' database flag for a Cloud SQL Mysql instance is set to 'off'", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'MYSQL',
        name: 'test-mysql-instance',
        settings: {
          databaseFlags: [
            {
              name: 'local_infile',
              value: 'off',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_613 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all MYSQL instances have the 'local_infile' set to 'off'", async () => {
      const data = {
        id: 'db-id',
        databaseVersion: 'MYSQL',
        name: 'test-mysql-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'local_infile',
              value: 'off',
            },
          ],
        },
      }
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the MYSQL instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the MYSQL instances do NOT have a 'local_infile' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the MYSQL instances do have a 'local_infile' database flag set to 'on'", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.1 Ensure 'log_error_verbosity' database flag for Cloud SQL PostgreSQL instance is set to 'DEFAULT' or stricter", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'POSTGRES',
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'log_error_verbosity',
              value: 'default',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_621 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all POSTGRES instances have the 'log_error_verbosity' set to 'default'", async () => {
      const data = {
        id: 'db-id',
        databaseVersion: 'POSTGRES',
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'log_error_verbosity',
              value: 'default',
            },
          ],
        },
      }
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_error_verbosity' set to 'terse'", async () => {
      const data = {
        id: 'db-id',
        databaseVersion: 'POSTGRES',
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'log_error_verbosity',
              value: 'terse',
            },
          ],
        },
      }
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_error_verbosity' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_error_verbosity' database flag set to 'default' or 'terse'", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = 'dummy-value'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.2 Ensure that the 'log_connections' database flag for Cloud SQL PostgreSQL instance is set to 'on'", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'POSTGRES',
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'log_connections',
              value: 'on',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_622 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all POSTGRES instances have the 'log_connections' set to 'on'", async () => {
      const data = {
        id: 'db-id',
        databaseVersion: 'POSTGRES',
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'log_connections',
              value: 'on',
            },
          ],
        },
      }
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_connections' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'on',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_connections' database flag set to 'off'", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = 'off'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.3 Ensure that the 'log_disconnections' database flag for Cloud SQL PostgreSQL instance is set to 'on'", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'POSTGRES',
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'log_disconnections',
              value: 'on',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_623 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all POSTGRES instances have the 'log_disconnections' set to 'on'", async () => {
      const data = {
        id: 'db-id',
        databaseVersion: 'POSTGRES',
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'log_disconnections',
              value: 'on',
            },
          ],
        },
      }
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_disconnections' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'on',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_disconnections' database flag set to 'off'", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = 'off'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.4 Ensure 'log_statement' database flag for Cloud SQL PostgreSQL instance is set appropriately", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'POSTGRES',
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'log_statement',
              value: 'ddl',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_624 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all POSTGRES instances have the 'log_statement' set to any value: ['ddl', 'mod', 'all', 'none']", async () => {
      const validValues = ['ddl', 'mod', 'all', 'none']
      for (const validValue of validValues) {
        const data = {
          id: 'db-id',
          databaseVersion: 'POSTGRES',

          name: 'test-postgres-instance',
          settings: {
            databaseFlags: [
              {
                name: 'dummy_key',
                value: 'on',
              },
              {
                name: 'log_statement',
                value: validValue,
              },
            ],
          },
        }
        await testRule(data, Result.PASS)
      }
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_statement' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_statement' database flag set to an invalid value", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = 'dummy'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.5 Ensure 'log_hostname' database flag for Cloud SQL PostgreSQL instance is set appropriately", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'POSTGRES',
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'log_hostname',
              value: 'on',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_625 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all POSTGRES instances have the 'log_hostname' set to 'on'", async () => {
      const data = {
        id: 'db-id',
        databaseVersion: 'POSTGRES',
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'log_hostname',
              value: 'on',
            },
          ],
        },
      }
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_hostname' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'on',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_hostname' database flag set to 'off'", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = 'off'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.6 Ensure that the 'log_min_messages' database flag for Cloud SQL PostgreSQL instance is set appropriately", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'POSTGRES',
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'log_min_messages',
              value: 'error',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_626 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all POSTGRES instances have the 'log_min_messages' set to any value: ['DEBUG5', 'DEBUG4', 'DEBUG3', 'DEBUG2', 'DEBUG1', 'INFO', 'NOTICE', 'WARNING', 'ERROR', 'LOG', 'FATAL', 'PANIC']", async () => {
      const validValues = [
        'DEBUG5',
        'DEBUG4',
        'DEBUG3',
        'DEBUG2',
        'DEBUG1',
        'INFO',
        'NOTICE',
        'WARNING',
        'ERROR',
        'LOG',
        'FATAL',
        'PANIC',
      ]
      for (const validValue of validValues) {
        const data = {
          id: 'db-id',
          databaseVersion: 'POSTGRES',

          name: 'test-postgres-instance',
          settings: {
            databaseFlags: [
              {
                name: 'dummy_key',
                value: 'on',
              },
              {
                name: 'log_min_messages',
                value: validValue,
              },
            ],
          },
        }
        await testRule(data, Result.PASS)
      }
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_min_messages' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_min_messages' database flag set to an invalid value", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = 'dummy'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.7 Ensure 'log_min_error_statement' database flag for Cloud SQL PostgreSQL instance is set to 'Error' or stricter", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'POSTGRES',
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'log_min_error_statement',
              value: 'error',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_627 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all POSTGRES instances have the 'log_min_error_statement' set to any value: ['error', 'log', 'fatal', 'panic']", async () => {
      const validValues = ['error', 'log', 'fatal', 'panic']
      for (const validValue of validValues) {
        const data = {
          id: 'db-id',
          databaseVersion: 'POSTGRES',

          name: 'test-postgres-instance',
          settings: {
            databaseFlags: [
              {
                name: 'dummy_key',
                value: 'on',
              },
              {
                name: 'log_min_error_statement',
                value: validValue,
              },
            ],
          },
        }
        await testRule(data, Result.PASS)
      }
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_min_error_statement' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_min_error_statement' database flag set to an invalid value", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = 'dummy'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.8 Ensure that the 'log_min_duration_statement' database flag for Cloud SQL PostgreSQL instance is set to '-1' (disabled)", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'POSTGRES',
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'log_min_duration_statement',
              value: '-1',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_628 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all POSTGRES instances have the 'log_min_duration_statement' set to '-1'", async () => {
      const data = {
        id: 'db-id',
        databaseVersion: 'POSTGRES',
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'log_min_duration_statement',
              value: '-1',
            },
          ],
        },
      }
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_min_duration_statement' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: '-1',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_min_duration_statement' database flag set to '100'", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = '100'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.3.1 Ensure 'external scripts enabled' database flag for Cloud SQL SQL Server instance is set to 'off'", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'SQLSERVER',
        name: 'test-sqlserver-instance',
        settings: {
          databaseFlags: [
            {
              name: 'external scripts enabled',
              value: 'off',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_631 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all SQLSERVER instances have the 'external scripts enabled' set to 'off'", async () => {
      const data = {
        id: 'db-id',
        databaseVersion: 'SQLSERVER',
        name: 'test-sqlserver-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'external scripts enabled',
              value: 'off',
            },
          ],
        },
      }
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the SQLSERVER instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do NOT have a 'external scripts enabled' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do have a 'external scripts enabled' database flag set to 'on'", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.3.2 Ensure that the 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off'", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'SQLSERVER',
        name: 'test-sqlserver-instance',
        settings: {
          databaseFlags: [
            {
              name: 'cross db ownership chaining',
              value: 'off',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_632 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all SQLSERVER instances have the 'cross db ownership chaining' set to 'off'", async () => {
      const data = {
        id: 'db-id',
        databaseVersion: 'SQLSERVER',
        name: 'test-sqlserver-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'cross db ownership chaining',
              value: 'off',
            },
          ],
        },
      }
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the SQLSERVER instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do NOT have a 'cross db ownership chaining' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do have a 'cross db ownership chaining' database flag set to 'on'", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.3.3 Ensure 'user connections' database flag for Cloud SQL SQL Server instance is set as appropriate", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'SQLSERVER',
        name: 'test-sqlserver-instance',
        settings: {
          databaseFlags: [
            {
              name: 'user connections',
              value: 'off',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_633 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all SQLSERVER instances have the 'user connections' set to 'off'", async () => {
      const data = {
        id: 'db-id',
        databaseVersion: 'SQLSERVER',
        name: 'test-sqlserver-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'user connections',
              value: 'some-value',
            },
          ],
        },
      }
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the SQLSERVER instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do NOT have a 'user connections' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do have a 'user connections' database flag set to null", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = null
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do have a 'user connections' database flag set to empty string", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = ''
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.3.4 Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'SQLSERVER',
        name: 'test-sqlserver-instance',
        settings: {
          databaseFlags: [
            {
              name: 'user options',
              value: null,
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_634 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all SQLSERVER instances have the 'user options' set to null or empty string", async () => {
      const data = {
        id: 'db-id',
        databaseVersion: 'SQLSERVER',
        name: 'test-sqlserver-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'user options',
              value: null,
            },
            {
              name: 'user options',
              value: '',
            },
          ],
        },
      }
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when the SQLSERVER instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.PASS)
    })

    test("Security Issue when the SQLSERVER instances do have a 'user options' database flag with value", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = 'some user options'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.3.5 Ensure 'remote access' database flag for Cloud SQL SQL Server instance is set to 'off'", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'SQLSERVER',
        name: 'test-sqlserver-instance',
        settings: {
          databaseFlags: [
            {
              name: 'remote access',
              value: 'off',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_635 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all SQLSERVER instances have the 'remote access' set to 'off'", async () => {
      const data = {
        id: 'db-id',
        databaseVersion: 'SQLSERVER',
        name: 'test-sqlserver-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'remote access',
              value: 'off',
            },
          ],
        },
      }
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the SQLSERVER instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do NOT have a 'remote access' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do have a 'remote access' database flag set to 'on'", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.3.6 Ensure '3625 (trace flag)' database flag for Cloud SQL SQL Server instance is set to 'off'", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'SQLSERVER',
        name: 'test-sqlserver-instance',
        settings: {
          databaseFlags: [
            {
              name: '3625 (trace flag)',
              value: 'off',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_636 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all SQLSERVER instances have the '3625 (trace flag)' set to 'off'", async () => {
      const data = {
        id: 'db-id',
        databaseVersion: 'SQLSERVER',
        name: 'test-sqlserver-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: '3625 (trace flag)',
              value: 'off',
            },
          ],
        },
      }
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the SQLSERVER instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do NOT have a '3625 (trace flag)' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do have a '3625 (trace flag)' database flag set to 'on'", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.3.7 Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is set to 'off'", () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: 'db-id',
        databaseVersion: 'SQLSERVER',
        name: 'test-sqlserver-instance',
        settings: {
          databaseFlags: [
            {
              name: 'contained database authentication',
              value: 'off',
            },
          ],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_637 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when all SQLSERVER instances have the 'contained database authentication' set to 'off'", async () => {
      const data = {
        id: 'db-id',
        databaseVersion: 'SQLSERVER',
        name: 'test-sqlserver-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'contained database authentication',
              value: 'off',
            },
          ],
        },
      }
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the SQLSERVER instances have no database flags', async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do NOT have a 'contained database authentication' database flag", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do have a 'contained database authentication' database flag set to 'on'", async () => {
      const data = getRuleFixture()
      data.settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 6.4 Ensure that the Cloud SQL database instance requires all incoming connections to use SSL', () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: cuid(),
        name: 'test-sql-instance',
        databaseVersion: 'SQLSERVER',
        settings: {
          ipConfiguration: {
            requireSsl: true,
          },
          databaseFlags: [],
        },
      }
    }
    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_64 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when requireSsl is set to true', async () => {
      const data = getRuleFixture()
      await testRule(data, Result.PASS)
    })

    test('Security Issue when requireSsl is set to false', async () => {
      const data = getRuleFixture()
      data.settings.ipConfiguration!.requireSsl = false
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when requireSsl is set to null', async () => {
      const data = getRuleFixture()
      data.settings.ipConfiguration!.requireSsl = null
      await testRule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 6.5 Ensure that Cloud SQL database instances are not open to the world', () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: cuid(),
        name: 'test-sql-instance',
        databaseVersion: 'SQLSERVER',
        settings: {
          ipConfiguration: {
            authorizedNetworks: [
              { value: '192.168.0.0/24' },
              { value: '192.168.1.0/24' },
            ],
          },
          databaseFlags: [],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_65 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when authorizedNetworks is NOT set to '0.0.0.0/0'", async () => {
      const data = getRuleFixture()
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when authorizedNetworks is empty', async () => {
      const data = getRuleFixture()
      data.settings = {
        ipConfiguration: {
          authorizedNetworks: [],
        },
        databaseFlags: [],
      }
      await testRule(data, Result.PASS)
    })

    test("Security Issue when authorizedNetworks is set to '0.0.0.0/0'", async () => {
      const data = getRuleFixture()
      data.settings = {
        ipConfiguration: {
          authorizedNetworks: [{ value: '0.0.0.0/0' }],
        },
        databaseFlags: [],
      }
      await testRule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 6.6 Ensure that Cloud SQL database instances do not have public IPs', () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: cuid(),
        name: 'test-sql-instance',
        databaseVersion: 'SQLSERVER',
        instanceType: 'CLOUD_SQL_INSTANCE',
        backendType: 'SECOND_GEN',
        ipAddresses: [
          {
            type: 'PRIVATE',
          },
        ],
        settings: {
          databaseFlags: [],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_66 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ipAddresses are PRIVATE', async () => {
      const data = getRuleFixture()
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when ipAddresses are empty', async () => {
      const data = getRuleFixture()
      data.ipAddresses = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when ipAddresses are PUBLIC', async () => {
      const data = getRuleFixture()
      data.ipAddresses = [
        {
          type: 'PUBLIC',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when ipAddresses are PRIVATE and PUBLIC', async () => {
      const data = getRuleFixture()
      data.ipAddresses = [
        {
          type: 'PRIVATE',
        },
        {
          type: 'PUBLIC',
        },
      ]
      await testRule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 6.7 Ensure that Cloud SQL database instances are configured with automated backups', () => {
    const getRuleFixture = (): SqlInstances => {
      return {
        id: cuid(),
        name: 'test-sql-instance',
        databaseVersion: 'SQLSERVER',
        settings: {
          backupConfiguration: {
            enabled: true,
            startTime: '02:00',
          },
          databaseFlags: [],
        },
      }
    }

    const testRule = async (
      data: SqlInstances,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_67 as Rule,
        { querygcpSqlInstance: [data] }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when backupConfiguration is configured', async () => {
      const data = getRuleFixture()
      await testRule(data, Result.PASS)
    })

    test('Security Issue when backupConfiguration is NOT enabled (false)', async () => {
      const data = getRuleFixture()
      data.settings.backupConfiguration!.enabled = false
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when backupConfiguration is NOT enabled (null)', async () => {
      const data = getRuleFixture()
      data.settings.backupConfiguration!.enabled = null
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when backupConfiguration is enabled but startTime is null', async () => {
      const data = getRuleFixture()
      data.settings.backupConfiguration!.startTime = null
      await testRule(data, Result.FAIL)
    })
  })
})
