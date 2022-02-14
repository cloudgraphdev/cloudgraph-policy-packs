import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Aws_PCI_DSS_321_EC2_4 from '../rules/pci-dss-3.2.1-ec2-check-4'
import Aws_PCI_DSS_321_EC2_5 from '../rules/pci-dss-3.2.1-ec2-check-5'
import Aws_PCI_DSS_321_EC2_6 from '../rules/pci-dss-3.2.1-ec2-check-6'

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
  inboundRules?: InboundRulesEntity[]
  outboundRules?: OutboundRulesEntity[]
}
export interface CISsgQueryResponse {
  queryawsSecurityGroup: QueryawsSecurityGroupEntity[]
}

describe('PCI Data Security Standard: 3.2.1', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'PCI',
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
  })

  describe('EC2 Check 6: VPC flow logging should be enabled in all VPCs', () => {
    test('Should pass when flow logging is enabled for each VPC', async () => {
      const data = {
        queryawsVpc: [
          {
            id: cuid(),
            flowLogs: [
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
            flowLogs: [],
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
