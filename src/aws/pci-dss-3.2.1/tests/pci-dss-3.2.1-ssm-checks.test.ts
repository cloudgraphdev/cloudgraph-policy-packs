import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_Ssm_1 from '../rules/pci-dss-3.2.1-ssm-check-1'
import Aws_PCI_DSS_321_Ssm_2 from '../rules/pci-dss-3.2.1-ssm-check-2'
import Aws_PCI_DSS_321_Ssm_3 from '../rules/pci-dss-3.2.1-ssm-check-3'
import { initRuleEngine } from '../../../utils/test'

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'PCI')
  })

  describe('SSM Check 1: Amazon EC2 instances managed by Systems Manager should have a patch compliance status of COMPLIANT after a patch installation', () => {
    test('Should pass when it does not have any complianceItems', async () => {
      const data = {
        queryawsSystemsManagerInstance: [
          {
            id: cuid(),
            complianceItems: []
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Ssm_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when it has a non compliant item', async () => {
      const data = {
        queryawsSystemsManagerInstance: [
          {
            id: cuid(),
            complianceItems: [
              {
                complianceType: 'Patch',
                status: 'NON_COMPLIANT'
              }
            ]
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Ssm_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when it does not have any non compliant items', async () => {
      const data = {
        queryawsSystemsManagerInstance: [
          {
            id: cuid(),
            complianceItems: [
              {
                complianceType: 'Patch',
                status: 'COMPLIANT'
              }
            ]
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Ssm_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when it has at least one non-compliant item', async () => {
      const data = {
        queryawsSystemsManagerInstance: [
          {
            id: cuid(),
            complianceItems: [
              {
                complianceType: 'Patch',
                status: 'COMPLIANT'
              },
              {
                complianceType: 'Patch',
                status: 'NON_COMPLIANT'
              }
            ]
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Ssm_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('SSM Check 2: Instances managed by Systems Manager should have an association compliance status of COMPLIANT', () => {
    test('Should pass when it does not have any complianceItems', async () => {
      const data = {
        queryawsSystemsManagerInstance: [
          {
            id: cuid(),
            complianceItems: []
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Ssm_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when it has a non compliant item', async () => {
      const data = {
        queryawsSystemsManagerInstance: [
          {
            id: cuid(),
            complianceItems: [
              {
                complianceType: 'Association',
                status: 'NON_COMPLIANT'
              }
            ]
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Ssm_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when it does not have any non compliant items', async () => {
      const data = {
        queryawsSystemsManagerInstance: [
          {
            id: cuid(),
            complianceItems: [
              {
                complianceType: 'Association',
                status: 'COMPLIANT'
              }
            ]
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Ssm_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when it has at least one non-compliant item', async () => {
      const data = {
        queryawsSystemsManagerInstance: [
          {
            id: cuid(),
            complianceItems: [
              {
                complianceType: 'Association',
                status: 'COMPLIANT'
              },
              {
                complianceType: 'Association',
                status: 'NON_COMPLIANT'
              }
            ]
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Ssm_2 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('SSM Check 3: EC2 instances should be managed by AWS Systems Manager', () => {
    test('Should fail when it does not have a ssm instance attached', async () => {
      const data = {
        queryawsEc2: [
          {
            id: cuid(),
            systemsManagerInstance: []
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Ssm_3 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should pass when it does have an ssm instance attached', async () => {
      const data = {
        queryawsEc2: [
          {
            id: cuid(),
            systemsManagerInstance: [
              {
                id: cuid()
              }
            ]
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_Ssm_3 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })
})
