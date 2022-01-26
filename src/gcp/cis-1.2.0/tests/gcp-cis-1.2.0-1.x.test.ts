/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Gcp_CIS_120_11 from '../rules/gcp-cis-1.2.0-1.1'
import Gcp_CIS_120_15 from '../rules/gcp-cis-1.2.0-1.5'
import Gcp_CIS_120_16 from '../rules/gcp-cis-1.2.0-1.6'
import Gcp_CIS_120_18 from '../rules/gcp-cis-1.2.0-1.8'

export interface MetricDescriptor {
  type: string
}

export interface Bindings {
  members: string[]
  role?: string
}

export interface IamPolicy {
  bindings: Bindings[]
}

export interface Folder {
  iamPolicy: IamPolicy[]
}

export interface Project {
  iamPolicy: IamPolicy[]
}

export interface QuerygcpOrganization {
  id: string
  displayName: string
  project: Project[]
  folder: Folder[]
}

export interface QuerygcpProject {
  id: string
  iamPolicy: IamPolicy[]
}

export interface CIS1xQueryResponse {
  querygcpOrganization?: QuerygcpOrganization[]
  querygcpProject?: QuerygcpProject[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine('gcp', 'CIS')
  })

  describe('GCP CIS 1.1 Ensure that corporate login credentials are used', () => {
    const getTest11RuleFixture = (
      organizationName: string,
      projectNembers: string[],
      folderMemebers: string[]
    ): CIS1xQueryResponse => {
      return {
        querygcpOrganization: [
          {
            id: cuid(),
            displayName: organizationName,
            project: [
              {
                iamPolicy: [
                  {
                    bindings: [
                      {
                        members: projectNembers,
                      },
                    ],
                  },
                ],
              },
            ],
            folder: [
              {
                iamPolicy: [
                  {
                    bindings: [
                      {
                        members: folderMemebers,
                      },
                    ],
                  },
                ],
              },
            ],
          },
        ],
      }
    }

    const test11Rule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_11 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with no email accounts outside the organization domain', async () => {
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        'autocloud.dev',
        ['user:user1@autocloud.dev', 'user:user2@autocloud.dev'],
        ['user:user3@autocloud.dev', 'user:user4@autocloud.dev']
      )
      await test11Rule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with project members with email accounts outside the organization domain', async () => {
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        'autocloud.dev',
        ['user:user1@autocloud.dev', 'user:anyuser@gmail.com'],
        ['user:user3@autocloud.dev', 'user:user4@autocloud.dev']
      )
      await test11Rule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with folder members with email accounts outside the organization domain', async () => {
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        'autocloud.dev',
        ['user:user1@autocloud.dev', 'user:user2@autocloud.dev'],
        ['user:user3@autocloud.dev', 'user:anyuser@gmail.com']
      )
      await test11Rule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with project and folder members with email accounts outside the organization domain', async () => {
      const data: CIS1xQueryResponse = getTest11RuleFixture(
        'autocloud.dev',
        ['user:user1@autocloud.dev', 'user:anyuser@gmail.com'],
        ['user:user3@autocloud.dev', 'user:anyuser@gmail.com']
      )
      await test11Rule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 1.5 Ensure that Service Account has no Admin privileges', () => {
    const getTest15RuleFixture = (
      role: string,
      projectNembers: string[]
    ): CIS1xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            iamPolicy: [
              {
                bindings: [
                  {
                    role,
                    members: projectNembers,
                  },
                ],
              },
            ],
          },
        ],
      }
    }

    const test15Rule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_15 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with services accounts with viewer role', async () => {
      const data: CIS1xQueryResponse = getTest15RuleFixture('roles/viewer', [
        'serviceAccount:243921055556-compute@developer.gserviceaccount.com',
        'serviceAccount:243921055556@cloudservices.gserviceaccount.com',
      ])
      await test15Rule(data, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with services accounts with browser role', async () => {
      const data: CIS1xQueryResponse = getTest15RuleFixture('roles/browser', [
        'serviceAccount:243921055556-compute@developer.gserviceaccount.com',
        'serviceAccount:243921055556@cloudservices.gserviceaccount.com',
      ])
      await test15Rule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with services accounts with editor role', async () => {
      const data: CIS1xQueryResponse = getTest15RuleFixture('roles/editor', [
        'serviceAccount:243921055556-compute@developer.gserviceaccount.com',
        'serviceAccount:243921055556@cloudservices.gserviceaccount.com',
      ])
      await test15Rule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with services accounts with owner role', async () => {
      const data: CIS1xQueryResponse = getTest15RuleFixture('roles/owner', [
        'serviceAccount:243921055556-compute@developer.gserviceaccount.com',
        'serviceAccount:243921055556@cloudservices.gserviceaccount.com',
      ])
      await test15Rule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with services accounts with admin role', async () => {
      const data: CIS1xQueryResponse = getTest15RuleFixture(
        'roles/appengine.appAdmin',
        [
          'serviceAccount:243921055556-compute@developer.gserviceaccount.com',
          'serviceAccount:243921055556@cloudservices.gserviceaccount.com',
        ]
      )
      await test15Rule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 1.6 Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level', () => {
    const getTest16RuleFixture = (
      role: string,
      projectNembers: string[]
    ): CIS1xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            iamPolicy: [
              {
                bindings: [
                  {
                    role,
                    members: projectNembers,
                  },
                ],
              },
            ],
          },
        ],
      }
    }

    const test16Rule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_16 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with user accounts with securityReviewer role', async () => {
      const data: CIS1xQueryResponse = getTest16RuleFixture(
        'roles/iam.securityReviewer',
        ['user:user1@autocloud.dev', 'user:user2@autocloud.dev']
      )
      await test16Rule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with user accounts with serviceAccountUser role', async () => {
      const data: CIS1xQueryResponse = getTest16RuleFixture(
        'roles/iam.serviceAccountUser',
        ['user:user1@autocloud.dev', 'user:user2@autocloud.dev']
      )
      await test16Rule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with user accounts with serviceAccountTokenCreator role', async () => {
      const data: CIS1xQueryResponse = getTest16RuleFixture(
        'roles/iam.serviceAccountTokenCreator',
        ['user:user1@autocloud.dev', 'user:user2@autocloud.dev']
      )
      await test16Rule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 1.8 Ensure that Separation of duties is enforced while assigning service account related roles to users', () => {
    const getTest18RuleFixture = (
      role: string,
      projectNembers: string[]
    ): CIS1xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            iamPolicy: [
              {
                bindings: [
                  {
                    role,
                    members: projectNembers,
                  },
                ],
              },
            ],
          },
        ],
      }
    }

    const test18Rule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_18 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with user accounts with securityReviewer role', async () => {
      const data: CIS1xQueryResponse = getTest18RuleFixture(
        'roles/iam.securityReviewer',
        ['user:user1@autocloud.dev', 'user:user2@autocloud.dev']
      )
      await test18Rule(data, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with user accounts with serviceAccountAdmin role', async () => {
      const data: CIS1xQueryResponse = getTest18RuleFixture(
        'roles/iam.serviceAccountAdmin',
        ['user:user1@autocloud.dev', 'user:user2@autocloud.dev']
      )
      await test18Rule(data, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with user accounts with serviceAccountUser role', async () => {
      const data: CIS1xQueryResponse = getTest18RuleFixture(
        'roles/iam.serviceAccountUser',
        ['user:user1@autocloud.dev', 'user:user2@autocloud.dev']
      )
      await test18Rule(data, Result.FAIL)
    })
  })
})
