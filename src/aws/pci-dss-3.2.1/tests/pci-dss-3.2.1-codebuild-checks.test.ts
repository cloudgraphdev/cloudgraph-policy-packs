import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_Codebuild_1 from '../rules/pci-dss-3.2.1-codebuild-check-1'

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
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Codebuild_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
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
})
