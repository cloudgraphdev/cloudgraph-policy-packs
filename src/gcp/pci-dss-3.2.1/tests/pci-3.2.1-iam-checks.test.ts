import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_PCI_DSS_321_IAM_3 from '../rules/pci-dss-3.2.1-iam-check-3'
import Gcp_PCI_DSS_321_IAM_4 from '../rules/pci-dss-3.2.1-iam-check-4'

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

export interface Bindings {
  members: string[]
  role?: string
}
export interface IamPolicy {
  kmsCryptoKey?: string
  bindings: Bindings[]
}
export interface ApiKey {
  id: string
}

export interface QuerygcpProject {
  id: string
  iamPolicies?: IamPolicy[]
  apiKeys?: ApiKey[]
}

export interface CISIAMQueryResponse {
  querygcpProject?: QuerygcpProject[]
  querygcpIamPolicy?: QuerygcpIamPolicy[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'gcp', entityName: 'PCI'} )
  })
  
  describe('IAM Check 1: User-managed service accounts should not have admin privileges', () => {
    const getTestIAM3RuleFixture = (
      role: string,
      projectMembers: string[]
    ): CISIAMQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            iamPolicies: [
              {
                bindings: [
                  {
                    role,
                    members: projectMembers,
                  },
                ],
              },
            ],
          },
        ],
      }
    }

    const testIAM3Rule = async (
      data: CISIAMQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_IAM_3 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with services accounts with viewer role', async () => {
      const data: CISIAMQueryResponse = getTestIAM3RuleFixture('roles/viewer', [
        'serviceAccount:243921055556-compute@developer.gserviceaccount.com',
        'serviceAccount:243921055556@cloudservices.gserviceaccount.com',
      ])
      await testIAM3Rule(data, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with services accounts with browser role', async () => {
      const data: CISIAMQueryResponse = getTestIAM3RuleFixture('roles/browser', [
        'serviceAccount:243921055556-compute@developer.gserviceaccount.com',
        'serviceAccount:243921055556@cloudservices.gserviceaccount.com',
      ])
      await testIAM3Rule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with services accounts with editor role', async () => {
      const data: CISIAMQueryResponse = getTestIAM3RuleFixture('roles/editor', [
        'serviceAccount:243921055556-compute@developer.gserviceaccount.com',
        'serviceAccount:243921055556@cloudservices.gserviceaccount.com',
      ])
      await testIAM3Rule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with services accounts with owner role', async () => {
      const data: CISIAMQueryResponse = getTestIAM3RuleFixture('roles/owner', [
        'serviceAccount:243921055556-compute@developer.gserviceaccount.com',
        'serviceAccount:243921055556@cloudservices.gserviceaccount.com',
      ])
      await testIAM3Rule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with services accounts with admin role', async () => {
      const data: CISIAMQueryResponse = getTestIAM3RuleFixture(
        'roles/appengine.appAdmin',
        [
          'serviceAccount:243921055556-compute@developer.gserviceaccount.com',
          'serviceAccount:243921055556@cloudservices.gserviceaccount.com',
        ]
      )
      await testIAM3Rule(data, Result.FAIL)
    })
  })

  describe('IAM Check 2: IAM default audit log config should not exempt any users', () => {
    const getTestIAM4RuleFixture = (): CISIAMQueryResponse => {
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

    const testIAM4Rule = async (
      data: CISIAMQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_PCI_DSS_321_IAM_4 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is a auditConfig with logtype set to DATA_WRITES and DATA_READ for all services, and exemptedMembers is empty', async () => {
      const data: CISIAMQueryResponse = getTestIAM4RuleFixture()
      await testIAM4Rule(data, Result.PASS)
    })

    test('Security Issue when there is a auditConfig with logtype set to DATA_WRITES and DATA_READ for all services, and exemptedMembers is NOT empty', async () => {
      let data: CISIAMQueryResponse = {
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
      await testIAM4Rule(data, Result.FAIL)

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
      await testIAM4Rule(data, Result.FAIL)
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
      await testIAM4Rule(data, Result.FAIL)
    })

    test('Security Issue when there is a auditConfig without logtype set to DATA_WRITES', async () => {
      const data: CISIAMQueryResponse = {
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
      await testIAM4Rule(data, Result.FAIL)
    })

    test('Security Issue when there is a auditConfig without logtype set to DATA_READ', async () => {
      const data: CISIAMQueryResponse = {
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
      await testIAM4Rule(data, Result.FAIL)
    })

    test('Security Issue when there is a auditConfig with logtype set to DATA_WRITES and DATA_READ NOT set to allServices', async () => {
      const data: CISIAMQueryResponse = {
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
      await testIAM4Rule(data, Result.FAIL)
    })
  })
  
})
