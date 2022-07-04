/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Aws_CIS_120_41 from '../rules/aws-cis-1.2.0-4.1'
import Aws_CIS_120_42 from '../rules/aws-cis-1.2.0-4.2'
import Aws_CIS_120_43 from '../rules/aws-cis-1.2.0-4.3'

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
export interface CIS4xQueryResponse {
  queryawsSecurityGroup: QueryawsSecurityGroupEntity[]
}

describe('CIS Amazon Web Services Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({ providerName: 'aws', entityName: 'CIS'} )
  })
  describe('AWS CIS 4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22', () => {
    const test41Rule = async (
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

      const data: CIS4xQueryResponse = {
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
        Aws_CIS_120_41 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a random IPv4 address and port 22', async () => {
      await test41Rule(22, 22, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and port 80', async () => {
      await test41Rule(80, 80, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and port 80', async () => {
      await test41Rule(80, 80, ipV6WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port 22', async () => {
      await test41Rule(1000, 2000, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and a port range not including the port 22', async () => {
      await test41Rule(1000, 2000, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and a port range not including the port 22', async () => {
      await test41Rule(1000, 2000, ipV6WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and a port range not including the port 22 (multiple values)', async () => {
      await test41Rule(
        1000,
        2000,
        ipV6WildcardAddress,
        Result.PASS,
        true
      )
    })

    test('Security Issue when IPv4 wilcard address and port 22 ', async () => {
      await test41Rule(22, 22, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv6 wilcard address and port 22 ', async () => {
      await test41Rule(22, 22, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv4 wilcard address and port 22 (multiple values)', async () => {
      await test41Rule(
        22,
        22,
        ipV4WildcardAddress,
        Result.FAIL,
        true
      )
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and no port range is specified', async () => {
      await test41Rule(
        undefined,
        undefined,
        ipV4WildcardAddress,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and no port range is specified', async () => {
      await test41Rule(
        undefined,
        undefined,
        ipV6WildcardAddress,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and port range includes the port 22', async () => {
      await test41Rule(0, 1000, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and port range includes the port 22', async () => {
      await test41Rule(0, 1000, ipV6WildcardAddress, Result.FAIL)
    })
  })

  describe('AWS CIS 4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389', () => {
    const test42Rule = async (
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

      const data: CIS4xQueryResponse = {
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
        Aws_CIS_120_42 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a random IPv4 address and port 3389', async () => {
      await test42Rule(3389, 3389, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and port 80', async () => {
      await test42Rule(80, 80, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and port 80', async () => {
      await test42Rule(80, 80, ipV6WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port 3389', async () => {
      await test42Rule(1000, 2000, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and a port range not including the port 3389', async () => {
      await test42Rule(1000, 2000, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and a port range not including the port 3389', async () => {
      await test42Rule(1000, 2000, ipV6WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and a port range not including the port 3389 (multiple values)', async () => {
      await test42Rule(
        1000,
        2000,
        ipV6WildcardAddress,
        Result.PASS,
        true
      )
    })

    test('Security Issue when IPv4 wilcard address and port 3389 ', async () => {
      await test42Rule(3389, 3389, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv6 wilcard address and port 3389 ', async () => {
      await test42Rule(3389, 3389, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv4 wilcard address and port 3389 (multiple values)', async () => {
      await test42Rule(
        3389,
        3389,
        ipV4WildcardAddress,
        Result.FAIL,
        true
      )
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and no port range is specified', async () => {
      await test42Rule(
        undefined,
        undefined,
        ipV4WildcardAddress,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and no port range is specified', async () => {
      await test42Rule(
        undefined,
        undefined,
        ipV6WildcardAddress,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and port range includes the port 3389', async () => {
      await test42Rule(0, 5000, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and port range includes the port 3389', async () => {
      await test42Rule(0, 5000, ipV6WildcardAddress, Result.FAIL)
    })
  })

  describe('AWS CIS 4.3 Ensure the default security group of every VPC restricts all traffic (Scored)', () => {
    const test43Rule = async (
      ingressSource: string,
      egressDestination: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS4xQueryResponse = {
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
        Aws_CIS_120_43 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is not an inbound/outbound rules with the wildcard addresses', async () => {
      await test43Rule(
        '10.10.10.10/16',
        '2001:db8:3333:4444:5555:6666:7777:8888',
        Result.PASS
      )
    })

    test('Security Issue when there is an inbound rule with a IPv4 wilcard address', async () => {
      await test43Rule(ipV4WildcardAddress, '', Result.FAIL)
    })
    test('Security Issue when there is an inbound rule with a IPv6 wilcard address', async () => {
      await test43Rule(ipV6WildcardAddress, '', Result.FAIL)
    })
    test('Security Issue when there is an outbound rule with a IPv4 wilcard address', async () => {
      await test43Rule('', ipV4WildcardAddress, Result.FAIL)
    })
    test('Security Issue when there is an outbound rule with a IPv6 wilcard address', async () => {
      await test43Rule('', ipV6WildcardAddress, Result.FAIL)
    })
    test('Security Issue when there is an inbound and an outbound rule with a IPv4 wilcard address', async () => {
      await test43Rule(
        ipV4WildcardAddress,
        ipV4WildcardAddress,
        Result.FAIL
      )
    })
    test('Security Issue when there is an inbound and an outbound rule with a IPv6 wilcard address', async () => {
      await test43Rule(
        ipV6WildcardAddress,
        ipV6WildcardAddress,
        Result.FAIL
      )
    })
  })
})
