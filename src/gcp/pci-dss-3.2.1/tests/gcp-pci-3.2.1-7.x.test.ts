import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_PCI_DSS_321_71 from '../rules/pci-dss-3.2.1-7.1'
import Gcp_PCI_DSS_321_72 from '../rules/pci-dss-3.2.1-7.2'

export interface Bindings {
  members: string[]
  role?: string
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

export interface CIS7xQueryResponse {  
  querygcpIamPolicy?: QuerygcpIamPolicy[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'PCI'} )
  })  

  describe('GCP PCI 7.2 IAM default audit log config should not exempt any users', () => {
    const getTest72RuleFixture = (): CIS7xQueryResponse => {
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

    const test72Rule = async (
      data: CIS7xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_72 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is a auditConfig with logtype set to DATA_WRITES and DATA_READ for all services, and exemptedMembers is empty', async () => {
      const data: CIS7xQueryResponse = getTest72RuleFixture()
      await test72Rule(data, Result.PASS)
    })

    test('Security Issue when there is a auditConfig with logtype set to DATA_WRITES and DATA_READ for all services, and exemptedMembers is NOT empty', async () => {
      let data: CIS7xQueryResponse = {
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
      await test72Rule(data, Result.FAIL)

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
      await test72Rule(data, Result.FAIL)
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
      await test72Rule(data, Result.FAIL)
    })

    test('Security Issue when there is a auditConfig without logtype set to DATA_WRITES', async () => {
      const data: CIS7xQueryResponse = {
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
      await test72Rule(data, Result.FAIL)
    })

    test('Security Issue when there is a auditConfig without logtype set to DATA_READ', async () => {
      const data: CIS7xQueryResponse = {
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
      await test72Rule(data, Result.FAIL)
    })

    test('Security Issue when there is a auditConfig with logtype set to DATA_WRITES and DATA_READ NOT set to allServices', async () => {
      const data: CIS7xQueryResponse = {
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
      await test72Rule(data, Result.FAIL)
    })
  })

})
