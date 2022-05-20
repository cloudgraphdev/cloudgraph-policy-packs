/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Gcp_NIST_800_53_31 from '../rules/gcp-nist-800-53-rev4-3.1'
import Gcp_NIST_800_53_32 from '../rules/gcp-nist-800-53-rev4-3.2'
import Gcp_NIST_800_53_33 from '../rules/gcp-nist-800-53-rev4-3.3'
import Gcp_NIST_800_53_34 from '../rules/gcp-nist-800-53-rev4-3.4'
import Gcp_NIST_800_53_35 from '../rules/gcp-nist-800-53-rev4-3.5'
import Gcp_NIST_800_53_36 from '../rules/gcp-nist-800-53-rev4-3.6'
import Gcp_NIST_800_53_37 from '../rules/gcp-nist-800-53-rev4-3.7'
import Gcp_NIST_800_53_38 from '../rules/gcp-nist-800-53-rev4-3.8'

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

export interface AuditLogConfig {
  logType: string
  exemptedMembers: string[]
}

export interface AuditConfig {
  auditLogConfigs: AuditLogConfig[]
  service: string
  exemptedMembers: string[]
}

export interface QuerygcpIamPolicy {
  id: string
  auditConfigs: AuditConfig[]
}

export interface NIST3xQueryResponse {
  querygcpProject?: QuerygcpProject[]
  querygcpSqlInstance?: SqlInstances[]
  querygcpIamPolicy?: QuerygcpIamPolicy[]
}

describe('GCP NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'NIST'} )
  })

  describe('GCP NIST 3.1 IAM default audit log config should not exempt any users', () => {
    const getTestRuleFixture = (): NIST3xQueryResponse => {
      return {
        querygcpIamPolicy: [
          {
            id: cuid(),
            auditConfigs: [
              {
                auditLogConfigs: [
                  {
                    logType: 'DATA_WRITE',
                    exemptedMembers: [],
                  },
                  {
                    logType: 'DATA_READ',
                    exemptedMembers: [],
                  },
                ],
                service: 'allServices',
                exemptedMembers: [],
              },
            ],
          },
        ],
      }
    }

    const test21Rule = async (
      data: NIST3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_31 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is a auditConfig with logtype set to DATA_WRITES and DATA_READ for all services, and exemptedMembers is empty', async () => {
      const data: NIST3xQueryResponse = getTestRuleFixture()
      await test21Rule(data, Result.PASS)
    })

    test('Security Issue when there is a auditConfig with logtype set to DATA_WRITES and DATA_READ for all services, and exemptedMembers is NOT empty', async () => {
      let data: NIST3xQueryResponse = {
        querygcpIamPolicy: [
          {
            id: cuid(),
            auditConfigs: [
              {
                auditLogConfigs: [
                  {
                    logType: 'DATA_WRITES',
                    exemptedMembers: [],
                  },
                  {
                    logType: 'DATA_READ',
                    exemptedMembers: [],
                  },
                ],
                service: 'allServices',
                exemptedMembers: ['dummy-member'],
              },
            ],
          },
        ],
      }
      await test21Rule(data, Result.FAIL)

      data = {
        querygcpIamPolicy: [
          {
            id: cuid(),
            auditConfigs: [
              {
                auditLogConfigs: [
                  {
                    logType: 'DATA_WRITES',
                    exemptedMembers: ['dummy-member'],
                  },
                  {
                    logType: 'DATA_READ',
                    exemptedMembers: [],
                  },
                ],
                service: 'allServices',
                exemptedMembers: [],
              },
            ],
          },
        ],
      }
      await test21Rule(data, Result.FAIL)
      data = {
        querygcpIamPolicy: [
          {
            id: cuid(),
            auditConfigs: [
              {
                auditLogConfigs: [
                  {
                    logType: 'DATA_WRITES',
                    exemptedMembers: [],
                  },
                  {
                    logType: 'DATA_READ',
                    exemptedMembers: ['dummy-member'],
                  },
                ],
                service: 'allServices',
                exemptedMembers: [],
              },
            ],
          },
        ],
      }
      await test21Rule(data, Result.FAIL)
    })

    test('Security Issue when there is a auditConfig without logtype set to DATA_WRITES', async () => {
      const data: NIST3xQueryResponse = {
        querygcpIamPolicy: [
          {
            id: cuid(),
            auditConfigs: [
              {
                auditLogConfigs: [
                  {
                    logType: 'DATA_READ',
                    exemptedMembers: [],
                  },
                ],
                service: 'allServices',
                exemptedMembers: [],
              },
            ],
          },
        ],
      }
      await test21Rule(data, Result.FAIL)
    })

    test('Security Issue when there is a auditConfig without logtype set to DATA_READ', async () => {
      const data: NIST3xQueryResponse = {
        querygcpIamPolicy: [
          {
            id: cuid(),
            auditConfigs: [
              {
                auditLogConfigs: [
                  {
                    logType: 'DATA_WRITES',
                    exemptedMembers: [],
                  },
                ],
                service: 'allServices',
                exemptedMembers: [],
              },
            ],
          },
        ],
      }
      await test21Rule(data, Result.FAIL)
    })

    test('Security Issue when there is a auditConfig with logtype set to DATA_WRITES and DATA_READ NOT set to allServices', async () => {
      const data: NIST3xQueryResponse = {
        querygcpIamPolicy: [
          {
            id: cuid(),
            auditConfigs: [
              {
                auditLogConfigs: [
                  {
                    logType: 'DATA_WRITE',
                    exemptedMembers: [],
                  },
                  {
                    logType: 'DATA_READ',
                    exemptedMembers: [],
                  },
                ],
                service: 'dummy-service',
                exemptedMembers: [],
              },
            ],
          },
        ],
      }
      await test21Rule(data, Result.FAIL)
    })
  })

  describe("GCP NIST 3.2 PostgreSQL database instance 'log_checkpoints' database flag should be set to 'on'", () => {
    const getRuleFixture = (): NIST3xQueryResponse => {
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
      data: NIST3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_32 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_checkpoints' set to 'on'", async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
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
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_checkpoints' database flag", async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
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
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'off'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GGCP NIST 3.3 PostgreSQL database instance 'log_connections' database flag should be set to 'on'", () => {
    const getRuleFixture = (): NIST3xQueryResponse => {
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
      data: NIST3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_33 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_connections' set to 'on'", async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
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
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_connections' database flag", async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
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
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'off'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP NIST 3.4 PostgreSQL database instance 'log_disconnections' database flag should be set to 'on'", () => {
    const getRuleFixture = (): NIST3xQueryResponse => {
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
      data: NIST3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_34 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_disconnections' set to 'on'", async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
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
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_disconnections' database flag", async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
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
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'off'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP NIST 3.5 PostgreSQL database instance 'log_lock_waits' database flag should be set to 'on'", () => {
    const getRuleFixture = (): NIST3xQueryResponse => {
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
      data: NIST3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_35 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_lock_waits' set to 'on'", async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
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
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_lock_waits' database flag", async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
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
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'off'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP NIST 3.6 PostgreSQL database instance 'log_min_error_statement' database flag should be set appropriately", () => {
    const getRuleFixture = (): NIST3xQueryResponse => {
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
      data: NIST3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_36 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_min_error_statement' set to any value: ['error', 'log', 'fatal', 'panic']", async () => {
      const validValues = ['error', 'log', 'fatal', 'panic']
      for (const validValue of validValues) {
        const data: NIST3xQueryResponse = getRuleFixture()
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
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_min_error_statement' database flag", async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
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
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = 'dummy'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP NIST 3.7 PostgreSQL database instance 'log_temp_files' database flag should be set to '0' (on)", () => {
    const getRuleFixture = (): NIST3xQueryResponse => {
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
      data: NIST3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_37 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_temp_files' set to '0'", async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
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
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_temp_files' database flag", async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
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
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = '1'
      await testRule(data, Result.FAIL)
    })
  })

  describe("GCP NIST 3.8 PostgreSQL database instance 'log_min_duration_statement' database flag should be set to '-1' (disabled)", () => {
    const getRuleFixture = (): NIST3xQueryResponse => {
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
      data: NIST3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_NIST_800_53_38 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is NO POSTGRES instances', async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances = []
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when all POSTGRES instances have the 'log_min_duration_statement' set to '-1'", async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
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
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags = []
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when the POSTGRES instances do NOT have a 'log_min_duration_statement' database flag", async () => {
      const data: NIST3xQueryResponse = getRuleFixture()
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
      const data: NIST3xQueryResponse = getRuleFixture()
      const project = data.querygcpProject?.[0] as QuerygcpProject
      project.sqlInstances[0].settings.databaseFlags[0].value = '100'
      await testRule(data, Result.FAIL)
    })
  })
})
