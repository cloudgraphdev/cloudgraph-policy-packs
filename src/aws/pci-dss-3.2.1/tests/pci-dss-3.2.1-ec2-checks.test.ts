import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_EC2_1 from '../rules/pci-dss-3.2.1-ec2-check-1'
import Aws_PCI_DSS_321_EC2_2 from '../rules/pci-dss-3.2.1-ec2-check-2'
import Aws_PCI_DSS_321_EC2_4 from '../rules/pci-dss-3.2.1-ec2-check-4'
import Aws_PCI_DSS_321_EC2_5 from '../rules/pci-dss-3.2.1-ec2-check-5'
import Aws_PCI_DSS_321_EC2_6 from '../rules/pci-dss-3.2.1-ec2-check-6'
import { initRuleEngine } from '../../../utils/test'

const ipV4WildcardAddress = '0.0.0.0/0'
const ipV6WildcardAddress = '::/0'

export interface InboundRulesEntity {
  toPort?: number
  fromPort?: number
  source: string
}
export interface OutboundRulesEntity {
  toPort?: number
  fromPort?: number
  destination: string
}
export interface QueryawsSecurityGroupEntity {
  id: string
  name?: string
  inboundRules?: InboundRulesEntity[]
  outboundRules?: OutboundRulesEntity[]
}
export interface CISsgQueryResponse {
  queryawsSecurityGroup: QueryawsSecurityGroupEntity[]
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('aws', 'PCI')
  })

  describe('EC2 Check 1: Amazon EBS snapshots should not be publicly restorable', () => {
    test('Should pass when group is not set to all and it has a user id', async () => {
      const data = {
        queryawsEbsSnapshot: [
          {
            id: cuid(),
            permissions: [
              {
                group: 'users',
                userId: cuid(),
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_EC2_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when group is set to all', async () => {
      const data = {
        queryawsEbsSnapshot: [
          {
            id: cuid(),
            permissions: [
              {
                group: 'all',
                userId: cuid(),
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_EC2_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when group is not set to all, but it has not a user id', async () => {
      const data = {
        queryawsEbsSnapshot: [
          {
            id: cuid(),
            permissions: [
              {
                group: cuid(),
                userId: null,
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_EC2_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })

    test('Should fail when it does not have configured permissions', async () => {
      const data = {
        queryawsEbsSnapshot: [
          {
            id: cuid(),
            permissions: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_EC2_1 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })
  })

  describe('EC2 Check 2: VPC default security group should prohibit inbound and outbound traffic', () => {
    const testSgRule = async (
      ingressSource: string,
      egressDestination: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CISsgQueryResponse = {
        queryawsSecurityGroup: [
          {
            id: cuid(),
            name: 'default',
            inboundRules: [],
            outboundRules: [],
          },
        ],
      }
      if (ingressSource) {
        data.queryawsSecurityGroup[0].inboundRules?.push({
          source: ingressSource as string,
        })
      }
      if (egressDestination) {
        data.queryawsSecurityGroup[0].outboundRules?.push({
          destination: egressDestination as string,
        })
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_EC2_2 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is not an inbound/outbound rules with the wildcard addresses', async () => {
      await testSgRule(
        '10.10.10.10/16',
        '2001:db8:3333:4444:5555:6666:7777:8888',
        Result.PASS
      )
    })

    test('Security Issue when there is an inbound rule with a IPv4 wilcard address', async () => {
      await testSgRule(ipV4WildcardAddress, '', Result.FAIL)
    })
    test('Security Issue when there is an inbound rule with a IPv6 wilcard address', async () => {
      await testSgRule(ipV6WildcardAddress, '', Result.FAIL)
    })
    test('Security Issue when there is an outbound rule with a IPv4 wilcard address', async () => {
      await testSgRule('', ipV4WildcardAddress, Result.FAIL)
    })
    test('Security Issue when there is an outbound rule with a IPv6 wilcard address', async () => {
      await testSgRule('', ipV6WildcardAddress, Result.FAIL)
    })
    test('Security Issue when there is an inbound and an outbound rule with a IPv4 wilcard address', async () => {
      await testSgRule(ipV4WildcardAddress, ipV4WildcardAddress, Result.FAIL)
    })
    test('Security Issue when there is an inbound and an outbound rule with a IPv6 wilcard address', async () => {
      await testSgRule(ipV6WildcardAddress, ipV6WildcardAddress, Result.FAIL)
    })
  })

  describe('EC2 Check 4: Unused EC2 EIPs should be removed', () => {
    test('Should pass when there are not unused EIPs', async () => {
      const data = {
        queryawsEip: [
          {
            id: cuid(),
            instanceId: cuid(),
            ec2Instance: [
              {
                arn: cuid(),
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_EC2_4 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when there are unused EIPs', async () => {
      const data = {
        queryawsEip: [
          {
            id: cuid(),
            instanceId: null,
            ec2Instance: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_EC2_4 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })

  describe('EC2 Check 5: Security groups should not allow ingress from 0.0.0.0/0 to port 22', () => {
    const testSGRule = async (
      fromPort: number | undefined,
      toPort: number | undefined,
      sourceAddress: string,
      expectedResult: Result,
      includeRandomValidData = false
    ): Promise<void> => {
      // Arrange
      const validInboundRule = {
        toPort: 123,
        fromPort: 456,
        source: '10.10.10.10/16',
      }

      const data: CISsgQueryResponse = {
        queryawsSecurityGroup: [
          {
            id: cuid(),
            inboundRules: [
              {
                toPort,
                fromPort,
                source: sourceAddress,
              },
            ],
          },
        ],
      }

      if (includeRandomValidData) {
        data.queryawsSecurityGroup[0].inboundRules?.push(validInboundRule)
        data.queryawsSecurityGroup.push({
          id: cuid(),
          inboundRules: [validInboundRule, validInboundRule],
        })
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_EC2_5 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a random IPv4 address and port 22', async () => {
      await testSGRule(22, 22, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and port 80', async () => {
      await testSGRule(80, 80, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and port 80', async () => {
      await testSGRule(80, 80, ipV6WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port 22', async () => {
      await testSGRule(1000, 2000, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and a port range not including the port 22', async () => {
      await testSGRule(1000, 2000, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and a port range not including the port 22', async () => {
      await testSGRule(1000, 2000, ipV6WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and a port range not including the port 22 (multiple values)', async () => {
      await testSGRule(1000, 2000, ipV6WildcardAddress, Result.PASS, true)
    })

    test('Security Issue when IPv4 wilcard address and port 22 ', async () => {
      await testSGRule(22, 22, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv6 wilcard address and port 22 ', async () => {
      await testSGRule(22, 22, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv4 wilcard address and port 22 (multiple values)', async () => {
      await testSGRule(22, 22, ipV4WildcardAddress, Result.FAIL, true)
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and no port range is specified', async () => {
      await testSGRule(undefined, undefined, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and no port range is specified', async () => {
      await testSGRule(undefined, undefined, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and port range includes the port 22', async () => {
      await testSGRule(0, 1000, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and port range includes the port 22', async () => {
      await testSGRule(0, 1000, ipV6WildcardAddress, Result.FAIL)
    })

    test('No Security Issue when there is an inbound rule with security group as source', async () => {
      await testSGRule(undefined, undefined, 'sg-049c76f349f62e4eb', Result.PASS)
    })
  })

  describe('EC2 Check 6: VPC flow logging should be enabled in all VPCs', () => {
    test('Should pass when flow logging is enabled for each VPC', async () => {
      const data = {
        queryawsVpc: [
          {
            id: cuid(),
            flowLog: [
              {
                resourceId: cuid(),
              },
            ],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_EC2_6 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.PASS)
    })

    test('Should fail when flow logging is disabled on one VPC', async () => {
      const data = {
        queryawsVpc: [
          {
            id: cuid(),
            flowLog: [],
          },
        ],
      }

      const [processedRule] = await rulesEngine.processRule(
        Aws_PCI_DSS_321_EC2_6 as Rule,
        { ...data } as any
      )

      expect(processedRule.result).toBe(Result.FAIL)
    })
  })
})
