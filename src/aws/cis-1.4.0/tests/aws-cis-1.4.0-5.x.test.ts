import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import cuid from 'cuid'

import Aws_CIS_140_51 from '../rules/aws-cis-1.4.0-5.1'
import Aws_CIS_140_52 from '../rules/aws-cis-1.4.0-5.2'
import Aws_CIS_140_53 from '../rules/aws-cis-1.4.0-5.3'

const ipV4WildcardAddress = '0.0.0.0/0'
const ipV6WildcardAddress = '::/0'

export interface InboundRule {
  source?: string
  toPort?: number | null
  fromPort?: number | null
  protocol?: string
  allowOrDeny?: string
}

export interface OutboundRule {
  destination?: string
  toPort?: number | null
  fromPort?: number | null
  protocol?: string
}

export interface QueryawsSecurityGroup {
  id: string
  name?: string
  inboundRules?: InboundRule[]
  outboundRules?: OutboundRule[]
}

export interface QueryawsNetworkAcl {
  id: string
  inboundRules?: InboundRule[]
  outboundRules?: OutboundRule[]
}

export interface QueryResponse {
  queryawsNetworkAcl?: QueryawsNetworkAcl[]
  queryawsSecurityGroup: QueryawsSecurityGroup[]
}

describe('CIS Amazon Web Services Foundations: 1.4.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'CIS',
    })
  })

  describe('AWS CIS 5.1 Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports', () => {
    const test51Rule = async (
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
        allowOrDeny: 'allow'
      }
  
      const data: QueryResponse = {
        queryawsSecurityGroup: [],
        queryawsNetworkAcl: [
          {
            id: cuid(),
            inboundRules: [
              {
                toPort,
                fromPort,
                source: sourceAddress,
                allowOrDeny: 'allow'
              },
            ],
          },
        ],
      }
  
      if (includeRandomValidData) {
        data.queryawsNetworkAcl?.[0].inboundRules?.push(validInboundRule)
        data.queryawsNetworkAcl?.push({
          id: cuid(),
          inboundRules: [validInboundRule, validInboundRule],
        })
      }
  
      // Act
      const [processedRule] = await rulesEngine.processRule(Aws_CIS_140_51 as Rule, { ...data })
  
      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a random IPv4 address and port 22', async () => {
      await test51Rule(22, 22, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random IPv4 address and port 3389', async () => {
      await test51Rule(3389, 3389, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wildcard address and port 80', async () => {
      await test51Rule(80, 80, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wildcard address and port 80', async () => {
      await test51Rule(80, 80, ipV6WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port 22', async () => {
      await test51Rule(
        100,
        200,
        '10.10.10.10/16',
        Result.PASS
      )
    })

    test('No Security Issue when there is an inbound rule with IPv4 wildcard address and a port range not including the port 3389', async () => {
      await test51Rule(
        1000,
        2000,
        ipV4WildcardAddress,
        Result.PASS
      )
    })

    test('No Security Issue when there is an inbound rule with IPv6 wildcard address and a port range not including the port 22', async () => {
      await test51Rule(
        100,
        200,
        ipV6WildcardAddress,
        Result.PASS
      )
    })

    test('No Security Issue when there is an inbound rule with IPv6 wildcard address and a port range not including the port 3389 (multiple values)', async () => {
      await test51Rule(
        1000,
        2000,
        ipV6WildcardAddress,
        Result.PASS,
        true
      )
    })

    test('Security Issue when IPv4 wildcard address and port 22', async () => {
      await test51Rule(22, 22, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv6 wildcard address and port 3389', async () => {
      await test51Rule(3389, 3389, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv4 wildcard address and port 22 (multiple values)', async () => {
      await test51Rule(
        22,
        22,
        ipV4WildcardAddress,
        Result.FAIL,
        true
      )
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and no port range is specified', async () => {
      await test51Rule(
        undefined,
        undefined,
        ipV4WildcardAddress,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and no port range is specified', async () => {
      await test51Rule(
        undefined,
        undefined,
        ipV6WildcardAddress,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and port range includes the port 22', async () => {
      await test51Rule(0, 100, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and port range includes the port 22', async () => {
      await test51Rule(0, 100, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and port range includes the port 3389', async () => {
      await test51Rule(3000, 4000, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and port range includes the port 3389', async () => {
      await test51Rule(3000, 4000, ipV6WildcardAddress, Result.FAIL)
    })
  })

  describe('AWS CIS 5.2 Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports', () => {
    const testRule = async (
      fromPort: number | null ,
      toPort: number | null,
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
  
      const data: QueryResponse = {
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
        data.queryawsSecurityGroup?.[0].inboundRules?.push(validInboundRule)
        data.queryawsSecurityGroup?.push({
          id: cuid(),
          inboundRules: [validInboundRule, validInboundRule],
        })
      }
  
      // Act
      const [processedRule] = await rulesEngine.processRule(Aws_CIS_140_52 as Rule, { ...data })
  
      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a random IPv4 address and port 22', async () => {
      await testRule(22, 22, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random IPv4 address and port 3389', async () => {
      await testRule(3389, 3389, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wildcard address and port 80', async () => {
      await testRule(80, 80, ipV6WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port 22', async () => {
      await testRule(
        100,
        200,
        '10.10.10.10/16',
        Result.PASS
      )
    })

    test('No Security Issue when there is an inbound rule with IPv4 wildcard address and a port range not including the port 3389', async () => {
      await testRule(
        1000,
        2000,
        ipV4WildcardAddress,
        Result.PASS
      )
    })

    test('No Security Issue when there is an inbound rule with IPv6 wildcard address and a port range not including the port 22', async () => {
      await testRule(
        100,
        200,
        ipV6WildcardAddress,
        Result.PASS
      )
    })

    test('No Security Issue when there is an inbound rule with IPv6 wildcard address and a port range not including the port 3389 (multiple values)', async () => {
      await testRule(
        1000,
        2000,
        ipV6WildcardAddress,
        Result.PASS,
        true
      )
    })

    test('Security Issue when IPv4 wildcard address and port 22', async () => {
      await testRule(22, 22, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv6 wildcard address and port 3389', async () => {
      await testRule(3389, 3389, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv4 wildcard address and port 22 (multiple values)', async () => {
      await testRule(
        22,
        22,
        ipV4WildcardAddress,
        Result.FAIL,
        true
      )
    })

    test('Security Issue when IPv4 wildcard address and port 3389 (multiple values)', async () => {
      await testRule(
        3389,
        3389,
        ipV4WildcardAddress,
        Result.FAIL,
        true
      )
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and no port range is specified', async () => {
      await testRule(
        null,
        null,
        ipV4WildcardAddress,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and no port range is specified', async () => {
      await testRule(
        null,
        null,
        ipV6WildcardAddress,
        Result.FAIL
      )
    })

    test('Security Issue when there is an inbound rule with IPv4 wildcard address and port range includes the port 22', async () => {
      await testRule(0, 100, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wildcard address and port range includes the port 3389', async () => {
      await testRule(3000, 4000, ipV6WildcardAddress, Result.FAIL)
    })
  })

  describe('AWS CIS 5.3 Ensure the default security group of every VPC restricts all traffic', () => {
    const test53Rule = async (
      ingressSource: string,
      egressDestination: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: QueryResponse = {
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
        Aws_CIS_140_53 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is not an inbound/outbound rules with the wildcard addresses', async () => {
      await test53Rule(
        '10.10.10.10/16',
        '2001:db8:3333:4444:5555:6666:7777:8888',
        Result.PASS
      )
    })

    test('Security Issue when there is an inbound rule with a IPv4 wilcard address', async () => {
      await test53Rule(ipV4WildcardAddress, '', Result.FAIL)
    })
    test('Security Issue when there is an inbound rule with a IPv6 wilcard address', async () => {
      await test53Rule(ipV6WildcardAddress, '', Result.FAIL)
    })
    test('Security Issue when there is an outbound rule with a IPv4 wilcard address', async () => {
      await test53Rule('', ipV4WildcardAddress, Result.FAIL)
    })
    test('Security Issue when there is an outbound rule with a IPv6 wilcard address', async () => {
      await test53Rule('', ipV6WildcardAddress, Result.FAIL)
    })
    test('Security Issue when there is an inbound and an outbound rule with a IPv4 wilcard address', async () => {
      await test53Rule(
        ipV4WildcardAddress,
        ipV4WildcardAddress,
        Result.FAIL
      )
    })
    test('Security Issue when there is an inbound and an outbound rule with a IPv6 wilcard address', async () => {
      await test53Rule(
        ipV6WildcardAddress,
        ipV6WildcardAddress,
        Result.FAIL
      )
    })
  })
})
