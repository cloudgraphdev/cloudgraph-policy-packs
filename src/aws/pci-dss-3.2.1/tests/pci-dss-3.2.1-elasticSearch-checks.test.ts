import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_ElasticSearch_1 from '../rules/pci-dss-3.2.1-elasticSearch-check-1'
import Aws_PCI_DSS_321_ElasticSearch_2 from '../rules/pci-dss-3.2.1-elasticSearch-check-2'
import { initRuleEngine } from '../../../utils/test'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'PCI')
  })

  describe('ElasticSearch Check 1: ElasticSearch domains should be in a VPC', () => {
    test('Should pass when it has a vpc configured', async () => {
      const data = {
        queryawsElasticSearchDomain: [
          {
            id: cuid(),
            vpcOptions: {
              vpcId: cuid()
            }
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_ElasticSearch_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when it does not have a vpc configured', async () => {
      const data = {
        queryawsElasticSearchDomain: [
          {
            id: cuid(),
            vpcOptions: {
              vpcId: null
            }
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_ElasticSearch_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('ElasticSearch Check 2: Elasticsearch domains should have encryption at rest enabled', () => {
    test('Should pass when encryption at rest is enabled', async () => {
      const data = {
        queryawsElasticSearchDomain: [
          {
            id: cuid(),
            encryptionAtRestOptions: {
              enabled: true
            }
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_ElasticSearch_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when encryption at rest is not enabled', async () => {
      const data = {
        queryawsElasticSearchDomain: [
          {
            id: cuid(),
            encryptionAtRestOptions: {
              enabled: false
            }
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_ElasticSearch_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })
})
