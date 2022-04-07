/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Gcp_CIS_120_612 from '../rules/gcp-cis-1.2.0-6.1.2'
import Gcp_CIS_120_613 from '../rules/gcp-cis-1.2.0-6.1.3'
import Gcp_CIS_120_621 from '../rules/gcp-cis-1.2.0-6.2.1'
import Gcp_CIS_120_622 from '../rules/gcp-cis-1.2.0-6.2.2'
import Gcp_CIS_120_623 from '../rules/gcp-cis-1.2.0-6.2.3'
import Gcp_CIS_120_624 from '../rules/gcp-cis-1.2.0-6.2.4'
import Gcp_CIS_120_625 from '../rules/gcp-cis-1.2.0-6.2.5'
import Gcp_CIS_120_626 from '../rules/gcp-cis-1.2.0-6.2.6'
import Gcp_CIS_120_627 from '../rules/gcp-cis-1.2.0-6.2.7'
import Gcp_CIS_120_628 from '../rules/gcp-cis-1.2.0-6.2.8'
import Gcp_CIS_120_629 from '../rules/gcp-cis-1.2.0-6.2.9'
import Gcp_CIS_120_6210 from '../rules/gcp-cis-1.2.0-6.2.10'
import Gcp_CIS_120_6211 from '../rules/gcp-cis-1.2.0-6.2.11'
import Gcp_CIS_120_6212 from '../rules/gcp-cis-1.2.0-6.2.12'
import Gcp_CIS_120_6213 from '../rules/gcp-cis-1.2.0-6.2.13'
import Gcp_CIS_120_6214 from '../rules/gcp-cis-1.2.0-6.2.14'
import Gcp_CIS_120_6215 from '../rules/gcp-cis-1.2.0-6.2.15'
import Gcp_CIS_120_6216 from '../rules/gcp-cis-1.2.0-6.2.16'
import Gcp_CIS_120_631 from '../rules/gcp-cis-1.2.0-6.3.1'
import Gcp_CIS_120_632 from '../rules/gcp-cis-1.2.0-6.3.2'
import Gcp_CIS_120_633 from '../rules/gcp-cis-1.2.0-6.3.3'
import Gcp_CIS_120_634 from '../rules/gcp-cis-1.2.0-6.3.4'
import Gcp_CIS_120_635 from '../rules/gcp-cis-1.2.0-6.3.5'
import Gcp_CIS_120_636 from '../rules/gcp-cis-1.2.0-6.3.6'
import Gcp_CIS_120_637 from '../rules/gcp-cis-1.2.0-6.3.7'
import Gcp_CIS_120_64 from '../rules/gcp-cis-1.2.0-6.4'
import Gcp_CIS_120_65 from '../rules/gcp-cis-1.2.0-6.5'
import Gcp_CIS_120_66 from '../rules/gcp-cis-1.2.0-6.6'
import Gcp_CIS_120_67 from '../rules/gcp-cis-1.2.0-6.7'

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
  settings: Settings
  ipAddresses?: IpAddress[]
}

export interface QuerygcpProject {
  id: string
  sqlInstances: SqlInstances[]
}

export interface CIS6xQueryResponse {
  querygcpProject?: QuerygcpProject[]
  querygcpSqlInstance?: SqlInstances[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'CIS'} )
  })

  describe("GCP CIS 6.1.2 Ensure 'skip_show_database' database flag for Cloud SQL Mysql instance is set to 'on'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-mysql-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'skip_show_database',
                      value: 'on',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_612 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO MYSQL instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all MYSQL instances have the 'skip_show_database' set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
        name: 'test-mysql-instance',
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
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the MYSQL instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the MYSQL instances do NOT have a 'skip_show_database' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'on',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the MYSQL instances do have a 'skip_show_database' database flag set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'off'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.1.3 Ensure that the 'local_infile' database flag for a Cloud SQL Mysql instance is set to 'off'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-mysql-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'local_infile',
                      value: 'off',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_613 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO MYSQL instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all MYSQL instances have the 'local_infile' set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
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
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the MYSQL instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the MYSQL instances do NOT have a 'local_infile' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the MYSQL instances do have a 'local_infile' database flag set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.1 Ensure that the 'log_checkpoints' database flag for Cloud SQL PostgreSQL instance is set to 'on'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_checkpoints',
                      value: 'on',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_621 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_checkpoints' set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'log_checkpoints',
              value: 'on',
            },
          ],
        },
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_checkpoints' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'on',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_checkpoints' database flag set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'off'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.2 Ensure 'log_error_verbosity' database flag for Cloud SQL PostgreSQL instance is set to 'DEFAULT' or stricter", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_error_verbosity',
                      value: 'default',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_622 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_error_verbosity' set to 'default'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
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
      })
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_error_verbosity' set to 'terse'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
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
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_error_verbosity' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_error_verbosity' database flag set to 'default' or 'terse'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'dummy-value'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.3 Ensure that the 'log_connections' database flag for Cloud SQL PostgreSQL instance is set to 'on'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_connections',
                      value: 'on',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_623 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_connections' set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
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
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_connections' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'on',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_connections' database flag set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'off'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.4 Ensure that the 'log_disconnections' database flag for Cloud SQL PostgreSQL instance is set to 'on'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_disconnections',
                      value: 'on',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_624 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_disconnections' set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
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
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_disconnections' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'on',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_disconnections' database flag set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'off'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.5 Ensure 'log_duration' database flag for Cloud SQL PostgreSQL instance is set to 'on'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_duration',
                      value: 'on',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_625 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_duration' set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'log_duration',
              value: 'on',
            },
          ],
        },
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_duration' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'on',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_duration' database flag set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'off'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.6 Ensure that the 'log_lock_waits' database flag for Cloud SQL PostgreSQL instance is set to 'on'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_lock_waits',
                      value: 'on',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_626 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_lock_waits' set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'log_lock_waits',
              value: 'on',
            },
          ],
        },
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_lock_waits' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'on',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_lock_waits' database flag set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'off'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.7 Ensure 'log_statement' database flag for Cloud SQL PostgreSQL instance is set appropriately", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_statement',
                      value: 'ddl',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_627 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_statement' set to any value: ['ddl', 'mod', 'all', 'none']", async () => {
      const validValues = ['ddl', 'mod', 'all', 'none']
      for (const validValue of validValues) {
        const data: CIS6xQueryResponse = getRuleFixture()
        const project = data.querygcpProject?.[0] as QuerygcpProject
        project.sqlInstances[0].settings.databaseFlags[0].value = validValue
        project.sqlInstances.push({
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
        })
        await testRule(data, Result.PASS)
      }
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_statement' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_statement' database flag set to an invalid value", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'dummy'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.8 Ensure 'log_hostname' database flag for Cloud SQL PostgreSQL instance is set appropriately", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_hostname',
                      value: 'on',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_628 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_hostname' set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
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
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_hostname' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'on',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_hostname' database flag set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'off'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.9 Ensure 'log_parser_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_parser_stats',
                      value: 'off',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_629 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_parser_stats' set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'log_parser_stats',
              value: 'off',
            },
          ],
        },
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_parser_stats' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_parser_stats' database flag set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.10 Ensure 'log_planner_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_planner_stats',
                      value: 'off',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_6210 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_planner_stats' set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'log_planner_stats',
              value: 'off',
            },
          ],
        },
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_planner_stats' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_planner_stats' database flag set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.11 Ensure 'log_executor_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_executor_stats',
                      value: 'off',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_6211 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_executor_stats' set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'log_executor_stats',
              value: 'off',
            },
          ],
        },
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_executor_stats' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_executor_stats' database flag set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.12 Ensure 'log_statement_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_statement_stats',
                      value: 'off',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_6212 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_statement_stats' set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'log_statement_stats',
              value: 'off',
            },
          ],
        },
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_statement_stats' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_statement_stats' database flag set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.13 Ensure that the 'log_min_messages' database flag for Cloud SQL PostgreSQL instance is set appropriately", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_min_messages',
                      value: 'error',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_6213 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

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
        const data: CIS6xQueryResponse = getRuleFixture()
        const project = data.querygcpProject?.[0] as QuerygcpProject
        project.sqlInstances[0].settings.databaseFlags[0].value = validValue
        project.sqlInstances.push({
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
        })
        await testRule(data, Result.PASS)
      }
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_min_messages' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_min_messages' database flag set to an invalid value", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'dummy'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.14 Ensure 'log_min_error_statement' database flag for Cloud SQL PostgreSQL instance is set to 'Error' or stricter", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_min_error_statement',
                      value: 'error',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_6214 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_min_error_statement' set to any value: ['error', 'log', 'fatal', 'panic']", async () => {
      const validValues = ['error', 'log', 'fatal', 'panic']
      for (const validValue of validValues) {
        const data: CIS6xQueryResponse = getRuleFixture()
        const project = data.querygcpProject?.[0] as QuerygcpProject
        project.sqlInstances[0].settings.databaseFlags[0].value = validValue
        project.sqlInstances.push({
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
        })
        await testRule(data, Result.PASS)
      }
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_min_error_statement' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_min_error_statement' database flag set to an invalid value", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'dummy'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.15 Ensure that the 'log_temp_files' database flag for Cloud SQL PostgreSQL instance is set to '0' (on)", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_temp_files',
                      value: '0',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_6215 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_temp_files' set to '0'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
        name: 'test-postgres-instance',
        settings: {
          databaseFlags: [
            {
              name: 'dummy_key',
              value: 'on',
            },
            {
              name: 'log_temp_files',
              value: '0',
            },
          ],
        },
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_temp_files' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_temp_files' database flag set to '1'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = '1'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.2.16 Ensure that the 'log_min_duration_statement' database flag for Cloud SQL PostgreSQL instance is set to '-1' (disabled)", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-postgres-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'log_min_duration_statement',
                      value: '-1',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_6216 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_min_duration_statement' set to '-1'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
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
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the POSTGRES instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_min_duration_statement' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: '-1',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do have a 'log_min_duration_statement' database flag set to '100'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = '100'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.3.1 Ensure 'external scripts enabled' database flag for Cloud SQL SQL Server instance is set to 'off'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-sqlserver-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'external scripts enabled',
                      value: 'off',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_631 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO SQLSERVER instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all SQLSERVER instances have the 'external scripts enabled' set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
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
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the SQLSERVER instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do NOT have a 'external scripts enabled' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do have a 'external scripts enabled' database flag set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.3.2 Ensure that the 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-sqlserver-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'cross db ownership chaining',
                      value: 'off',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_632 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO SQLSERVER instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all SQLSERVER instances have the 'cross db ownership chaining' set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
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
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the SQLSERVER instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do NOT have a 'cross db ownership chaining' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do have a 'cross db ownership chaining' database flag set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.3.3 Ensure 'user connections' database flag for Cloud SQL SQL Server instance is set as appropriate", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-sqlserver-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'user connections',
                      value: 'off',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_633 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO SQLSERVER instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all SQLSERVER instances have the 'user connections' set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
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
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the SQLSERVER instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do NOT have a 'user connections' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do have a 'user connections' database flag set to null", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = null
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do have a 'user connections' database flag set to empty string", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = ''
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.3.4 Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-sqlserver-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'user options',
                      value: null,
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_634 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO SQLSERVER instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all SQLSERVER instances have the 'user options' set to null or empty string", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
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
      })
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when the SQLSERVER instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.PASS)
    })

    test("Security Issue when the SQLSERVER instances do have a 'user options' database flag with value", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'some user options'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.3.5 Ensure 'remote access' database flag for Cloud SQL SQL Server instance is set to 'off'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-sqlserver-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'remote access',
                      value: 'off',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_635 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO SQLSERVER instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all SQLSERVER instances have the 'remote access' set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
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
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the SQLSERVER instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do NOT have a 'remote access' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do have a 'remote access' database flag set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.3.6 Ensure '3625 (trace flag)' database flag for Cloud SQL SQL Server instance is set to 'off'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-sqlserver-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: '3625 (trace flag)',
                      value: 'off',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_636 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO SQLSERVER instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all SQLSERVER instances have the '3625 (trace flag)' set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
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
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the SQLSERVER instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do NOT have a '3625 (trace flag)' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do have a '3625 (trace flag)' database flag set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP CIS 6.3.7 Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is set to 'off'", () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            sqlInstances: [
              {
                name: 'test-sqlserver-instance',
                settings: {
                  databaseFlags: [
                    {
                      name: 'contained database authentication',
                      value: 'off',
                    },
                  ],
                },
              },
            ],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_637 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO SQLSERVER instances', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all SQLSERVER instances have the 'contained database authentication' set to 'off'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances.push({
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
      })
      await testRule(data, Result.PASS)
    })

    test('Security Issue when the SQLSERVER instances have no database flags', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do NOT have a 'contained database authentication' database flag", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = [
        {
          name: 'dummy_key',
          value: 'off',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the SQLSERVER instances do have a 'contained database authentication' database flag set to 'on'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'on'
      await testRule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 6.4 Ensure that the Cloud SQL database instance requires all incoming connections to use SSL', () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpSqlInstance: [
          {
            id: cuid(),
            name: 'test-sql-instance',
            settings: {
              ipConfiguration: {
                requireSsl: true,
              },
              databaseFlags: [],
            },
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_64 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when requireSsl is set to true', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      await testRule(data, Result.PASS)
    })

    test('Security Issue when requireSsl is set to false', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      const ipConfiguration = sqlInstance.settings
        .ipConfiguration as IpConfiguration
      ipConfiguration.requireSsl = false
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when requireSsl is set to null', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      const ipConfiguration = sqlInstance.settings
        .ipConfiguration as IpConfiguration
      ipConfiguration.requireSsl = null
      await testRule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 6.5 Ensure that Cloud SQL database instances are not open to the world', () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpSqlInstance: [
          {
            id: cuid(),
            name: 'test-sql-instance',
            settings: {
              ipConfiguration: {
                authorizedNetworks: [
                  { value: '192.168.0.0/24' },
                  { value: '192.168.1.0/24' },
                ],
              },
              databaseFlags: [],
            },
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_65 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test("No Security Issue when authorizedNetworks is NOT set to '0.0.0.0/0'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when authorizedNetworks is empty', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      sqlInstance.settings = {
        ipConfiguration: {
          authorizedNetworks: [],
        },
        databaseFlags: [],
      }
      await testRule(data, Result.PASS)
    })

    test("Security Issue when authorizedNetworks is set to '0.0.0.0/0'", async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      sqlInstance.settings = {
        ipConfiguration: {
          authorizedNetworks: [{ value: '0.0.0.0/0' }],
        },
        databaseFlags: [],
      }
      await testRule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 6.6 Ensure that Cloud SQL database instances do not have public IPs', () => {
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpSqlInstance: [
          {
            id: cuid(),
            name: 'test-sql-instance',
            ipAddresses: [
              {
                type: 'PRIVATE',
              },
            ],
            settings: {
              databaseFlags: [],
            },
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_66 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when ipAddresses are PRIVATE', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when ipAddresses are empty', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      sqlInstance.ipAddresses = []
      await testRule(data, Result.PASS)
    })

    test('Security Issue when ipAddresses are PUBLIC', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      sqlInstance.ipAddresses = [
        {
          type: 'PUBLIC',
        },
      ]
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when ipAddresses are PRIVATE and PUBLIC', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      sqlInstance.ipAddresses = [
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
    const getRuleFixture = (): CIS6xQueryResponse => {
      return {
        querygcpSqlInstance: [
          {
            id: cuid(),
            name: 'test-sql-instance',
            settings: {
              backupConfiguration: {
                enabled: true,
                startTime: '02:00',
              },
              databaseFlags: [],
            },
          },
        ],
      }
    }

    const testRule = async (
      data: CIS6xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_67 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when backupConfiguration is configured', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      await testRule(data, Result.PASS)
    })

    test('Security Issue when backupConfiguration is NOT enabled (false)', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      const backupConfiguration = sqlInstance.settings
        .backupConfiguration as BackupConfiguration
      backupConfiguration.enabled = false
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when backupConfiguration is NOT enabled (null)', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      const backupConfiguration = sqlInstance.settings
        .backupConfiguration as BackupConfiguration
      backupConfiguration.enabled = null
      await testRule(data, Result.FAIL)
    })

    test('Security Issue when backupConfiguration is enabled but startTime is null', async () => {
      const data: CIS6xQueryResponse = getRuleFixture()
      const sqlInstance = data.querygcpSqlInstance?.[0] as SqlInstances
      const backupConfiguration = sqlInstance.settings
        .backupConfiguration as BackupConfiguration
      backupConfiguration.startTime = null
      await testRule(data, Result.FAIL)
    })
  })
})
