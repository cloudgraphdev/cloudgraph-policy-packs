import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_Rds_1 from '../rules/pci-dss-3.2.1-rds-check-1'
import Aws_PCI_DSS_321_Rds_2 from '../rules/pci-dss-3.2.1-rds-check-2'
import { initRuleEngine } from '../../../utils/test'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'PCI')
  })
  describe('RDS check 1: RDS snapshots should prohibit public access', () => {
    test('Should fail when snapshots have a resotre - all attribute', async () => {
      const data = {
        queryawsRdsClusterSnapshot: [
          {
            id: cuid(),
            attributes: [
              {
                name: 'restore',
                values: ['all']
              }
            ]
          }
        ]
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Rds_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when snapshots does not have a resotre - all attribute', async () => {
      const data = {
        queryawsRdsClusterSnapshot: [
          {
            id: cuid(),
            attributes: [
              {
                name: 'restore',
                values: [cuid()]
              }
            ]
          }
        ]
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Rds_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should pass when snapshots has multiple attributes, one being a resotre without all attribute', async () => {
      const data = {
        queryawsRdsClusterSnapshot: [
          {
            id: cuid(),
            attributes: [
              {
                name: 'test',
                values: ['all']
              },
              {
                name: 'restore',
                values: [cuid()]
              }
            ]
          }
        ]
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Rds_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when snapshots has multiple values in the restore attribute, one being all', async () => {
      const data = {
        queryawsRdsClusterSnapshot: [
          {
            id: cuid(),
            attributes: [
              {
                name: 'test',
                values: ['all']
              },
              {
                name: 'restore',
                values: [cuid(), 'all']
              }
            ]
          }
        ]
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Rds_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    }) 
  })
  describe('RDS Check 2: RDS DB Instances should prohibit public access', () => {
    test('Should fail when publiclyAccessible is true', async () => {
      const data = {
        queryawsRdsDbInstance: [
          {
            id: cuid(),
            publiclyAccessible: true
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Rds_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when publiclyAccessible is false', async () => {
      const data = {
        queryawsRdsDbInstance: [
          {
            id: cuid(),
            publiclyAccessible: false
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Rds_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })
})
