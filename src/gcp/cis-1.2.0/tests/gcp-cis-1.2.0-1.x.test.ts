/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Gcp_CIS_120_11 from '../rules/gcp-cis-1.2.0-1.1'
import Gcp_CIS_120_15 from '../rules/gcp-cis-1.2.0-1.5'
import Gcp_CIS_120_16 from '../rules/gcp-cis-1.2.0-1.6'
import Gcp_CIS_120_18 from '../rules/gcp-cis-1.2.0-1.8'
import Gcp_CIS_120_112 from '../rules/gcp-cis-1.2.0-1.12'
import Gcp_CIS_120_113 from '../rules/gcp-cis-1.2.0-1.13'
import Gcp_CIS_120_115 from '../rules/gcp-cis-1.2.0-1.15'

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
export interface ApiKey {
  id: string
}
export interface Folder {
  iamPolicy: IamPolicy[]
}
export interface Project {
  iamPolicy: IamPolicy[]
}
export interface ApiTarget {
  service: string
}
export interface BrowserKeyRestrictions {
  allowedReferrers: string[]
}
export interface ServerKeyRestrictions {
  allowedIps: string[]
}
export interface AndroidAllowedApplication {
  packageName: string
}
export interface AndroidKeyRestrictions {
  allowedApplications: AndroidAllowedApplication[]
}
export interface IosKeyRestrictions {
  allowedBundleIds: string[]
}
export interface QuerygcpApiKey {
  id: string
  apiTargets?: ApiTarget[]
  browserKeyRestrictions?: BrowserKeyRestrictions
  serverKeyRestrictions?: ServerKeyRestrictions
  androidKeyRestrictions?: AndroidKeyRestrictions
  iosKeyRestrictions?: IosKeyRestrictions
  createTime?: string
}

export interface QuerygcpOrganization {
  id: string
  displayName: string
  project: Project[]
  folder: Folder[]
}

export interface QuerygcpProject {
  id: string
  iamPolicy?: IamPolicy[]
  apiKeys?: ApiKey[]
}
export interface CIS1xQueryResponse {
  querygcpOrganization?: QuerygcpOrganization[]
  querygcpProject?: QuerygcpProject[]
  querygcpApiKey?: QuerygcpApiKey[]
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

  describe('GCP CIS 1.12 Ensure API keys are not created for a project', () => {
    const getRuleFixture = (): CIS1xQueryResponse => {
      return {
        querygcpProject: [
          {
            id: cuid(),
            apiKeys: [],
          },
        ],
      }
    }

    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_112 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are no Api Keys', async () => {
      const data: CIS1xQueryResponse = getRuleFixture()
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there are Api Keys for a project', async () => {
      const data: CIS1xQueryResponse = getRuleFixture()
      const projects = data.querygcpProject as QuerygcpProject[]
      projects[0].apiKeys = [{ id: 'dummy-api-key-id' }]
      await testRule(data, Result.FAIL)
    })
  })

  describe('GCP CIS 1.13 Ensure API keys are restricted to use by only specified Hosts and Apps', () => {
    const getRuleFixture = (): CIS1xQueryResponse => {
      return {
        querygcpApiKey: [
          {
            id: cuid(),
          },
        ],
      }
    }

    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_113 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there are android apps restrictions', async () => {
      const data: CIS1xQueryResponse = getRuleFixture()
      const apiKeys = data.querygcpApiKey as QuerygcpApiKey[]
      apiKeys[0].androidKeyRestrictions = {
        allowedApplications: [{ packageName: 'dummy-android-package-name' }],
      }
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when there are ios apps restrictions', async () => {
      const data: CIS1xQueryResponse = getRuleFixture()
      const apiKeys = data.querygcpApiKey as QuerygcpApiKey[]
      apiKeys[0].iosKeyRestrictions = {
        allowedBundleIds: ['dummy-ios-bundle-id'],
      }
      await testRule(data, Result.PASS)
    })

    test('No Security Issue when there are browserKeyRestrictions with HTTP referrers not containing wildcards', async () => {
      const data: CIS1xQueryResponse = getRuleFixture()
      const apiKeys = data.querygcpApiKey as QuerygcpApiKey[]
      apiKeys[0].browserKeyRestrictions = {
        allowedReferrers: ['example.com'],
      }
      await testRule(data, Result.PASS)
    })

    test("No Security Issue when there are serverKeyRestrictions with Ip addresses not set to 'any host'", async () => {
      const data: CIS1xQueryResponse = getRuleFixture()
      const apiKeys = data.querygcpApiKey as QuerygcpApiKey[]
      apiKeys[0].serverKeyRestrictions = {
        allowedIps: ['192.162.1.0/24'],
      }
      await testRule(data, Result.PASS)
    })

    test('Security Issue when there are no restrictions', async () => {
      const data: CIS1xQueryResponse = getRuleFixture()
      const apiKey = (data.querygcpApiKey as QuerygcpApiKey[])[0]
      apiKey.browserKeyRestrictions = undefined
      apiKey.serverKeyRestrictions = undefined
      apiKey.androidKeyRestrictions = undefined
      apiKey.iosKeyRestrictions = undefined
      await testRule(data, Result.FAIL)
    })

    test("Security Issue when there are browserKeyRestrictions with HTTP referrers containing wildcards ('0.0.0.0', '0.0.0.0/0', '::0')", async () => {
      const notAllowedReferrers = ['*', '*.com', '*.com/*']
      for (const notAllowedReferrer of notAllowedReferrers) {
        const data: CIS1xQueryResponse = getRuleFixture()
        const apiKeys = data.querygcpApiKey as QuerygcpApiKey[]
        apiKeys[0].browserKeyRestrictions = {
          allowedReferrers: [notAllowedReferrer],
        }
        await testRule(data, Result.FAIL)
      }
    })

    test("Security Issue when there are serverKeyRestrictions with Ip addresses not set to 'any host'", async () => {
      const anyNetworks = ['0.0.0.0', '0.0.0.0/0', '::0']
      for (const anyNetwork of anyNetworks) {
        const data: CIS1xQueryResponse = getRuleFixture()
        const apiKeys = data.querygcpApiKey as QuerygcpApiKey[]
        apiKeys[0].serverKeyRestrictions = {
          allowedIps: [anyNetwork],
        }
        await testRule(data, Result.FAIL)
      }
    })
  })

  describe('GCP CIS 1.15 Ensure API keys are rotated every 90 days', () => {
    const getRuleFixture = (): CIS1xQueryResponse => {
      return {
        querygcpApiKey: [
          {
            id: cuid(),
            createTime: new Date().toISOString(),
          },
        ],
      }
    }

    const testRule = async (
      data: CIS1xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_115 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when they Api Key was created less than 90 days ago', async () => {
      const data: CIS1xQueryResponse = getRuleFixture()
      await testRule(data, Result.PASS)
    })

    test('Security Issue when they Api Key was created 90 days or more ago', async () => {
      const data: CIS1xQueryResponse = getRuleFixture()
      const apiKeys = data.querygcpApiKey as QuerygcpApiKey[]
      const date = new Date()
      date.setDate(date.getDate() - 90)
      apiKeys[0].createTime = date.toISOString()
      await testRule(data, Result.FAIL)
    })
  })
})
