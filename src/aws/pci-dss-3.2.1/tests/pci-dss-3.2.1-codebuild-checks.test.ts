import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_Codebuild_1 from '../rules/pci-dss-3.2.1-codebuild-check-1'
import Aws_PCI_DSS_321_Codebuild_2 from '../rules/pci-dss-3.2.1-codebuild-check-2'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'PCI',
    })
  })

  describe('CodeBuild Check 1: CodeBuild GitHub or Bitbucket source repository URLs should use OAuth', () => {
    test('Should fail when the source is different than Github or Bitbucket', async () => {
      const data = {
        queryawsCodebuild: [
          {
            id: cuid(),
            source: {
              type: 'CODEPIPELINE',
              auth: null,
            },
          },
          {
            id: cuid(),
            source: {
              type: 'GITHUB',
              auth: {
                type: null,
              },
            },
          },
        ],
      }

      const processedRules = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Codebuild_1 as Rule,
        { ...data } as any
      )

      let passedRules = 0
      let failedRules = 0
      processedRules.forEach((processedRule) =>
        processedRule.result === Result.FAIL ? failedRules++ : passedRules++
      )

      expect(passedRules).toBe(1)
      expect(failedRules).toBe(1)
    })

    test('Should pass when the source comes from GITHUB and it uses OAUTH', async () => {
      const data = {
        queryawsCodebuild: [
          {
            id: cuid(),
            source: {
              type: 'GITHUB',
              auth: {
                type: 'OAUTH',
              },
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Codebuild_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass when the source comes from BITBUCKET and it uses OAUTH', async () => {
      const data = {
        queryawsCodebuild: [
          {
            id: cuid(),
            source: {
              type: 'BITBUCKET',
              auth: {
                type: 'OAUTH',
              },
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Codebuild_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('CodeBuild Check 2: CloudTrail should be enabled', () => {
    test('Should fail when the SECRET is set as plaintext env variable', async () => {
      const data = {
        queryawsCodebuild: [
          {
            id: cuid(),
            environment: {
              environmentVariables: [
                {
                  type: 'PLAINTEXT',
                  name: 'SECRET',
                },
              ],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Codebuild_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when the ACCESS_KEY is set as plaintext env variable', async () => {
      const data = {
        queryawsCodebuild: [
          {
            id: cuid(),
            environment: {
              environmentVariables: [
                {
                  type: 'PLAINTEXT',
                  name: 'ACCESS_KEY',
                },
              ],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Codebuild_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when the PASSWORD is set as plaintext env variable', async () => {
      const data = {
        queryawsCodebuild: [
          {
            id: cuid(),
            environment: {
              environmentVariables: [
                {
                  type: 'PLAINTEXT',
                  name: 'PASSWORD',
                },
              ],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Codebuild_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when any other env variable is set as plaintext', async () => {
      const data = {
        queryawsCodebuild: [
          {
            id: cuid(),
            environment: {
              environmentVariables: [
                {
                  type: 'PLAINTEXT',
                  name: 'FOUNDATION',
                },
              ],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Codebuild_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass when there are not env variables configured', async () => {
      const data = {
        queryawsCodebuild: [
          {
            id: cuid(),
            environment: {
              environmentVariables: [],
            },
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Codebuild_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })
})
