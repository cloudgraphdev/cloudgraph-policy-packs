/* eslint-disable max-len */
import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Gcp_CIS_120_31 from '../rules/gcp-cis-1.2.0-3.1'
import Gcp_CIS_120_32 from '../rules/gcp-cis-1.2.0-3.2'
import Gcp_CIS_120_33 from '../rules/gcp-cis-1.2.0-3.3'
import Gcp_CIS_120_34 from '../rules/gcp-cis-1.2.0-3.4'
import Gcp_CIS_120_35 from '../rules/gcp-cis-1.2.0-3.5'
import Gcp_CIS_120_36 from '../rules/gcp-cis-1.2.0-3.6'
import Gcp_CIS_120_37 from '../rules/gcp-cis-1.2.0-3.7'
import Gcp_CIS_120_38 from '../rules/gcp-cis-1.2.0-3.8'
import Gcp_CIS_120_39 from '../rules/gcp-cis-1.2.0-3.9'
import Gcp_CIS_120_310 from '../rules/gcp-cis-1.2.0-3.10'

const ipV4WildcardAddress = '0.0.0.0/0'
const ipV6WildcardAddress = '::/0'

export interface Allowed {
  ipProtocol: string
  ports: string[]
}

export interface QuerygcpFirewall {
  id: string
  sourceRanges: string[]
  direction: string
  allowed?: Allowed[]
}

export interface GcpNetworkSubnet {
  purpose: string
  enableFlowLogs: boolean | null
}

export interface QuerygcpNetwork {
  id: string
  subnets?: GcpNetworkSubnet[]
  name?: string
  ipV4Range?: string | null
}

export interface DnssecConfigDefaultKeySpecs {
  keyType: string
  algorithm: string
}

export interface QuerygcpDnsManagedZone {
  id: string
  visibility?: string
  dnssecConfigState?: string
  dnssecConfigDefaultKeySpecs?: DnssecConfigDefaultKeySpecs[]
}

export interface SslPolicy {
  profile: string
  enabledFeatures?: string[]
  minTlsVersion: string
}

export interface TargetHttpsProxy {
  sslPolicy?: SslPolicy[]
}

export interface TargetSslProxy {
  sslPolicy?: SslPolicy[]
}

export interface QuerygcpTargetSslProxy {
  id: string
  sslPolicy?: SslPolicy[]
}
export interface QuerygcpTargetHttpsProxy {
  id: string
  sslPolicy?: SslPolicy[]
}

export interface CIS3xQueryResponse {
  querygcpFirewall?: QuerygcpFirewall[]
  querygcpNetwork?: QuerygcpNetwork[]
  querygcpDnsManagedZone?: QuerygcpDnsManagedZone[]
  querygcpTargetSslProxy?: QuerygcpTargetSslProxy[]
  querygcpTargetHttpsProxy?: QuerygcpTargetHttpsProxy[]
}

describe('CIS Google Cloud Platform Foundations: 1.2.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'gcp',
      entityName: 'CIS',
    })
  })
  describe('GCP CIS 3.1 Ensure that the default network does not exist in a project', () => {
    const test31Rule = async (
      networkName: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS3xQueryResponse = {
        querygcpNetwork: [
          {
            id: cuid(),
            name: networkName,
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_31 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a network name that is not equal to default', async () => {
      await test31Rule('test-network', Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a network name that is equal to default', async () => {
      await test31Rule('default', Result.FAIL)
    })
  })

  describe('GCP CIS 3.2 Ensure legacy networks do not exist for a project', () => {
    const test32Rule = async (
      networkIpV4Range: string | null,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS3xQueryResponse = {
        querygcpNetwork: [
          {
            id: cuid(),
            ipV4Range: networkIpV4Range,
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_32 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a not set ipV4Range', async () => {
      await test32Rule(null, Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a not set ipV4Range', async () => {
      await test32Rule('192.168.0.0/16', Result.FAIL)
    })
  })

  describe('GCP CIS 3.3 Ensure that DNSSEC is enabled for Cloud DNS', () => {
    const test33Rule = async (
      visibility: string,
      dnssecConfigState: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS3xQueryResponse = {
        querygcpDnsManagedZone: [
          {
            id: cuid(),
            visibility,
            dnssecConfigState,
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_33 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with visibility public and dnssecConfigState is enabled', async () => {
      await test33Rule('public', 'on', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with visibility private and dnssecConfigState is not enabled', async () => {
      await test33Rule('private', 'off', Result.PASS)
    })

    test('Security Issue when there is an inbound rule with visibility public and dnssecConfigState is not enabled', async () => {
      await test33Rule('public', 'off', Result.FAIL)
    })
  })

  describe('GCP CIS 3.4 Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC', () => {
    const test34Rule = async (
      visibility: string,
      keyType: string,
      algorithm: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS3xQueryResponse = {
        querygcpDnsManagedZone: [
          {
            id: cuid(),
            visibility,
            dnssecConfigDefaultKeySpecs: [
              {
                keyType: 'keySigning',
                algorithm: 'rsasha512',
              },
              {
                keyType: 'keyTest',
                algorithm: 'rsasha1',
              },
              {
                keyType,
                algorithm,
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_34 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with visibility public and keyType keySigning and algorithm type different to rsasha1', async () => {
      await test34Rule('public', 'keySigning', 'rsasha256', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with visibility private and keyType keySigning and algorithm type rsasha1', async () => {
      await test34Rule('private', 'keySigning', 'rsasha256', Result.PASS)
    })

    test('Security Issue when there is an inbound rule with visibility public and keyType keySigning and algorithm type rsasha1', async () => {
      await test34Rule('public', 'keySigning', 'rsasha1', Result.FAIL)
    })
  })

  describe('GCP CIS 3.5 Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC', () => {
    const test35Rule = async (
      visibility: string,
      keyType: string,
      algorithm: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS3xQueryResponse = {
        querygcpDnsManagedZone: [
          {
            id: cuid(),
            visibility,
            dnssecConfigDefaultKeySpecs: [
              {
                keyType: 'zoneSigning',
                algorithm: 'rsasha512',
              },
              {
                keyType: 'keyTest',
                algorithm: 'rsasha1',
              },
              {
                keyType,
                algorithm,
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_35 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with visibility public and keyType zoneSigning and algorithm type different to rsasha1', async () => {
      await test35Rule('public', 'zoneSigning', 'rsasha256', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with visibility private and keyType zoneSigning and algorithm type rsasha1', async () => {
      await test35Rule('private', 'zoneSigning', 'rsasha256', Result.PASS)
    })

    test('Security Issue when there is an inbound rule with visibility public and keyType zoneSigning and algorithm type rsasha1', async () => {
      await test35Rule('public', 'zoneSigning', 'rsasha1', Result.FAIL)
    })
  })

  describe('GCP CIS 3.6 Ensure that SSH access is restricted from the internet', () => {
    const test36Rule = async (
      fromPort: number | undefined,
      toPort: number | undefined,
      sourceAddress: string,
      expectedResult: Result,
      protocol?: string
    ): Promise<void> => {
      // Arrange
      const data: CIS3xQueryResponse = {
        querygcpFirewall: [
          {
            id: cuid(),
            sourceRanges: [sourceAddress],
            direction: 'INGRESS',
            allowed: [
              {
                ipProtocol: 'icmp',
                ports: [],
              },
              {
                ipProtocol: protocol || 'tcp',
                ports: fromPort && toPort ? [`${fromPort}-${toPort}`] : [],
              },
              {
                ipProtocol: 'udp',
                ports: ['0-65535'],
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_36 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a random IPv4 address and port 22', async () => {
      await test36Rule(22, 22, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and port 80', async () => {
      await test36Rule(80, 80, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and port 80', async () => {
      await test36Rule(80, 80, ipV6WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port 22', async () => {
      await test36Rule(1000, 2000, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and a port range not including the port 22', async () => {
      await test36Rule(1000, 2000, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and a port range not including the port 22', async () => {
      await test36Rule(1000, 2000, ipV6WildcardAddress, Result.PASS)
    })

    test('Security Issue when IPv4 wilcard address and port 22 and tcp protocol', async () => {
      await test36Rule(22, 22, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv4 wilcard address and port 22 and all protocol', async () => {
      await test36Rule(22, 22, ipV4WildcardAddress, Result.FAIL, 'all')
    })

    test('Security Issue when IPv6 wilcard address and port 22 and tcp protocol', async () => {
      await test36Rule(22, 22, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv6 wilcard address and port 22 and all protocol', async () => {
      await test36Rule(22, 22, ipV6WildcardAddress, Result.FAIL, 'all')
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and no port range is specified', async () => {
      await test36Rule(undefined, undefined, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and no port range is specified', async () => {
      await test36Rule(undefined, undefined, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and port range includes the port 22', async () => {
      await test36Rule(0, 1000, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and port range includes the port 22', async () => {
      await test36Rule(0, 1000, ipV6WildcardAddress, Result.FAIL)
    })
  })

  describe('GCP CIS 3.7 Ensure that RDP access is restricted from the internet', () => {
    const test37Rule = async (
      fromPort: number | undefined,
      toPort: number | undefined,
      sourceAddress: string,
      expectedResult: Result,
      protocol?: string
    ): Promise<void> => {
      // Arrange
      const data: CIS3xQueryResponse = {
        querygcpFirewall: [
          {
            id: cuid(),
            sourceRanges: [sourceAddress],
            direction: 'INGRESS',
            allowed: [
              {
                ipProtocol: 'icmp',
                ports: [],
              },
              {
                ipProtocol: protocol || 'tcp',
                ports: fromPort && toPort ? [`${fromPort}-${toPort}`] : [],
              },
              {
                ipProtocol: 'udp',
                ports: ['0-65535'],
              },
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_37 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a random IPv4 address and port 3986', async () => {
      await test37Rule(3986, 3986, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and port 80', async () => {
      await test37Rule(80, 80, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and port 80', async () => {
      await test37Rule(80, 80, ipV6WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with a random IPv4 and a port range not including the port 3986', async () => {
      await test37Rule(1000, 2000, '10.10.10.10/16', Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv4 wilcard address and a port range not including the port 3986', async () => {
      await test37Rule(1000, 2000, ipV4WildcardAddress, Result.PASS)
    })

    test('No Security Issue when there is an inbound rule with IPv6 wilcard address and a port range not including the port 3986', async () => {
      await test37Rule(1000, 2000, ipV6WildcardAddress, Result.PASS)
    })

    test('Security Issue when IPv4 wilcard address and port 3986 and tcp protocol', async () => {
      await test37Rule(3986, 3986, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv4 wilcard address and port 3986 and all protocol', async () => {
      await test37Rule(3986, 3986, ipV4WildcardAddress, Result.FAIL, 'all')
    })

    test('Security Issue when IPv6 wilcard address and port 3986 and tcp protocol', async () => {
      await test37Rule(3986, 3986, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when IPv6 wilcard address and port 3986 and all protocol', async () => {
      await test37Rule(3986, 3986, ipV6WildcardAddress, Result.FAIL, 'all')
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and no port range is specified', async () => {
      await test37Rule(undefined, undefined, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and no port range is specified', async () => {
      await test37Rule(undefined, undefined, ipV6WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv4 wilcard address and port range includes the port 3986', async () => {
      await test37Rule(0, 4000, ipV4WildcardAddress, Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with IPv6 wilcard address and port range includes the port 3986', async () => {
      await test37Rule(0, 4000, ipV6WildcardAddress, Result.FAIL)
    })
  })

  describe('GCP CIS 3.8 Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network', () => {
    const test38Rule = async (
      subnets: GcpNetworkSubnet[],
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS3xQueryResponse = {
        querygcpNetwork: [
          {
            id: cuid(),
            subnets,
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_38 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when all PRIVATE subnets have enableFlowLogs set to true', async () => {
      const subnets: GcpNetworkSubnet[] = [
        {
          purpose: 'PRIVATE',
          enableFlowLogs: true,
        },
        {
          purpose: 'PRIVATE',
          enableFlowLogs: true,
        },
        {
          purpose: 'DUMMY',
          enableFlowLogs: null,
        },
        {
          purpose: 'DUMMY',
          enableFlowLogs: true,
        },
        {
          purpose: 'DUMMY',
          enableFlowLogs: false,
        },
      ]
      await test38Rule(subnets, Result.PASS)
    })

    test('Security Issue when at least 1 PRIVATE subnet has enableFlowLogs set to false', async () => {
      const subnets: GcpNetworkSubnet[] = [
        {
          purpose: 'PRIVATE',
          enableFlowLogs: true,
        },
        {
          purpose: 'PRIVATE',
          enableFlowLogs: false,
        },
      ]
      await test38Rule(subnets, Result.FAIL)
    })
    test('Security Issue when at least 1 PRIVATE subnet has enableFlowLogs set to null', async () => {
      const subnets: GcpNetworkSubnet[] = [
        {
          purpose: 'PRIVATE',
          enableFlowLogs: true,
        },
        {
          purpose: 'PRIVATE',
          enableFlowLogs: null,
        },
      ]
      await test38Rule(subnets, Result.FAIL)
    })
  })

  describe('GCP CIS 3.9 Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites', () => {

    const getTest39RuleAFixture = (): CIS3xQueryResponse => {
      return {
        querygcpTargetHttpsProxy: [
          {
            id: cuid(),
            sslPolicy: [
              {
                profile: 'MODERN',
                minTlsVersion: 'TLS_1_2',
              },
            ],
          },
        ],
      }
    }

    const getTest39RuleBFixture = (): CIS3xQueryResponse => {
      return {
        querygcpTargetSslProxy: [
          {
            id: cuid(),
            sslPolicy: [
              {
                profile: 'MODERN',
                minTlsVersion: 'TLS_1_2',
              },
            ],
          },
        ],
      }
    }

    const test39Rule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result,
      rule?: any
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(rule as Rule, {
        ...data,
      })

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    describe('querygcpTargetHttpsProxy query:', () => {
      let targetHttpsProxyRule: Rule
      beforeAll(() => {
        const { queries, ...ruleMetadata} = Gcp_CIS_120_39
        const query = queries.shift()
        targetHttpsProxyRule = {
          ...ruleMetadata,
          ...query
        } as Rule
      })

      test('No Security Issue when proxies and ssl policies are secure', async () => {
        const data: CIS3xQueryResponse = getTest39RuleAFixture()
        await test39Rule(data, Result.PASS, targetHttpsProxyRule)
      })
  
      test('Security Issue when proxies not have ssl policy', async () => {
        const data: CIS3xQueryResponse = getTest39RuleAFixture()
        const targetHttpsProxy = data
          .querygcpTargetHttpsProxy?.[0] as QuerygcpTargetHttpsProxy
        targetHttpsProxy.sslPolicy = []
        await test39Rule(data, Result.FAIL, targetHttpsProxyRule)
      })
  
      test('Security Issue when HTTPS-PROXY with MODERN ssl policy and VERSION is NOT TLS_1_2', async () => {
        const data: CIS3xQueryResponse = getTest39RuleAFixture()
        const targetHttpsProxy = data
          .querygcpTargetHttpsProxy?.[0] as QuerygcpTargetHttpsProxy
        targetHttpsProxy.sslPolicy = targetHttpsProxy.sslPolicy?.map(
          ({ minTlsVersion, ...p }) => {
            return {
              ...p,
              minTlsVersion: 'dummy',
            }
          }
        )
        await test39Rule(data, Result.FAIL, targetHttpsProxyRule)
      })
  
      test('Security Issue when HTTPS-PROXY with CUSTOM ssl policy and enabledFeatures contains invalid values', async () => {
        const invalidEnabledFeatureValues = [
          'TLS_RSA_WITH_AES_128_GCM_SHA256',
          'TLS_RSA_WITH_AES_256_GCM_SHA384',
          'TLS_RSA_WITH_AES_128_CBC_SHA',
          'TLS_RSA_WITH_AES_256_CBC_SHA',
          'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        ]
        for (const invalidEnabledFeatureValue of invalidEnabledFeatureValues) {
          const data: CIS3xQueryResponse = getTest39RuleAFixture()
          const targetHttpsProxy = data
          .querygcpTargetHttpsProxy?.[0] as QuerygcpTargetHttpsProxy
          targetHttpsProxy.sslPolicy = targetHttpsProxy.sslPolicy?.map(
            ({ enabledFeatures, profile, ...p }) => {
              return {
                ...p,
                profile: 'CUSTOM',
                enabledFeatures: [invalidEnabledFeatureValue],
              }
            }
          )
          await test39Rule(data, Result.FAIL, targetHttpsProxyRule)
        }
      })
    })

    describe('querygcpTargetSslProxy query:', () => {
      let targetSslProxyRule: Rule
      beforeAll(() => {
        const { queries, ...ruleMetadata} = Gcp_CIS_120_39
        const query = queries.shift()
        targetSslProxyRule = {
          ...ruleMetadata,
          ...query
        } as Rule
      })

      test('No Security Issue when proxies and ssl policies are secure', async () => {
        const data: CIS3xQueryResponse = getTest39RuleBFixture()
        await test39Rule(data, Result.PASS, targetSslProxyRule)
      })
  
      test('Security Issue when proxies not have ssl policy', async () => {
        const data: CIS3xQueryResponse = getTest39RuleBFixture()
        const targetSslProxy = data
          .querygcpTargetSslProxy?.[0] as QuerygcpTargetHttpsProxy
          targetSslProxy.sslPolicy = []
        await test39Rule(data, Result.FAIL, targetSslProxyRule)
      })
  
      test('Security Issue when HTTPS-PROXY with MODERN ssl policy and VERSION is NOT TLS_1_2', async () => {
        const data: CIS3xQueryResponse = getTest39RuleBFixture()
        const targetSslProxy = data
          .querygcpTargetSslProxy?.[0] as QuerygcpTargetHttpsProxy
          targetSslProxy.sslPolicy = targetSslProxy.sslPolicy?.map(
          ({ minTlsVersion, ...p }) => {
            return {
              ...p,
              minTlsVersion: 'dummy',
            }
          }
        )
        await test39Rule(data, Result.FAIL, targetSslProxyRule)
      })
  
      test('Security Issue when HTTPS-PROXY with CUSTOM ssl policy and enabledFeatures contains invalid values', async () => {
        const invalidEnabledFeatureValues = [
          'TLS_RSA_WITH_AES_128_GCM_SHA256',
          'TLS_RSA_WITH_AES_256_GCM_SHA384',
          'TLS_RSA_WITH_AES_128_CBC_SHA',
          'TLS_RSA_WITH_AES_256_CBC_SHA',
          'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        ]
        for (const invalidEnabledFeatureValue of invalidEnabledFeatureValues) {
          const data: CIS3xQueryResponse = getTest39RuleBFixture()
          const targetSslProxy = data
          .querygcpTargetSslProxy?.[0] as QuerygcpTargetHttpsProxy
          targetSslProxy.sslPolicy = targetSslProxy.sslPolicy?.map(
            ({ enabledFeatures, profile, ...p }) => {
              return {
                ...p,
                profile: 'CUSTOM',
                enabledFeatures: [invalidEnabledFeatureValue],
              }
            }
          )
          await test39Rule(data, Result.FAIL, targetSslProxyRule)
        }
      })
    })
  })

  describe('GCP CIS 3.10 Ensure Firewall Rules for instances behind Identity Aware Proxy (IAP) only allow the traffic from Google Cloud Loadbalancer (GCLB) Health Check and Proxy Addresses', () => {
    const getTest310RuleFixture = (
      sourceRanges: string[],
      allowed: Allowed[]
    ): CIS3xQueryResponse => {
      return {
        querygcpFirewall: [
          {
            id: cuid(),
            sourceRanges,
            direction: 'INGRESS',
            allowed,
          },
        ],
      }
    }

    const test310Rule = async (
      data: CIS3xQueryResponse,
      expectedResult: Result
    ): Promise<void> => {
      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_120_310 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when traffic from 35.191.0.0/16 tcp:80', async () => {
      const sourceRanges: string[] = ['35.191.0.0/16']
      const allowed: Allowed[] = [
        {
          ipProtocol: 'tcp',
          ports: ['80'],
        },
      ]
      const data: CIS3xQueryResponse = getTest310RuleFixture(
        sourceRanges,
        allowed
      )
      await test310Rule(data, Result.PASS)
    })

    test('No Security Issue when traffic from 130.211.0.0/22 tcp:80', async () => {
      const sourceRanges: string[] = ['130.211.0.0/22']
      const allowed: Allowed[] = [
        {
          ipProtocol: 'tcp',
          ports: ['80'],
        },
      ]
      const data: CIS3xQueryResponse = getTest310RuleFixture(
        sourceRanges,
        allowed
      )
      await test310Rule(data, Result.PASS)
    })

    test('No Security Issue when traffic from 130.211.0.0/22 tcp:80 and from 130.211.0.0/22 tcp:80', async () => {
      const sourceRanges: string[] = ['35.191.0.0/16', '130.211.0.0/22']
      const allowed: Allowed[] = [
        {
          ipProtocol: 'tcp',
          ports: ['80'],
        },
      ]
      const data: CIS3xQueryResponse = getTest310RuleFixture(
        sourceRanges,
        allowed
      )
      await test310Rule(data, Result.PASS)
    })

    test('Security Issue when traffic not from 130.211.0.0/22 tcp:80 or from 130.211.0.0/22 tcp:80', async () => {
      const sourceRanges: string[] = ['192.168.1.100/16']
      const allowed: Allowed[] = [
        {
          ipProtocol: 'tcp',
          ports: ['80'],
        },
      ]
      const data: CIS3xQueryResponse = getTest310RuleFixture(
        sourceRanges,
        allowed
      )
      await test310Rule(data, Result.FAIL)
    })

    test('Security Issue when traffic from 130.211.0.0/22 tcp:80 and from 192.168.1.100/16 tcp:80', async () => {
      const sourceRanges: string[] = ['130.211.0.0/22', '192.168.1.100/16']
      const allowed: Allowed[] = [
        {
          ipProtocol: 'tcp',
          ports: ['80'],
        },
      ]
      const data: CIS3xQueryResponse = getTest310RuleFixture(
        sourceRanges,
        allowed
      )
      await test310Rule(data, Result.FAIL)
    })

    test('Security Issue when traffic from 130.211.0.0/22 udp:80', async () => {
      const sourceRanges: string[] = ['35.191.0.0/16']
      const allowed: Allowed[] = [
        {
          ipProtocol: 'udp',
          ports: ['80'],
        },
      ]
      const data: CIS3xQueryResponse = getTest310RuleFixture(
        sourceRanges,
        allowed
      )
      await test310Rule(data, Result.FAIL)
    })

    test('Security Issue when traffic from 130.211.0.0/22 tcp:8080', async () => {
      const sourceRanges: string[] = ['35.191.0.0/16']
      const allowed: Allowed[] = [
        {
          ipProtocol: 'tcp',
          ports: ['8080'],
        },
      ]
      const data: CIS3xQueryResponse = getTest310RuleFixture(
        sourceRanges,
        allowed
      )
      await test310Rule(data, Result.FAIL)
    })
  })
})
