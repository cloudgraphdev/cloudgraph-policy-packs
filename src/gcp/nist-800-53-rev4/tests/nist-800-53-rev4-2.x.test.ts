import cuid from 'cuid'
import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

import Gcp_NIST_800_53_21 from '../rules/gcp-nist-800-53-rev4-2.1'
import Gcp_NIST_800_53_22 from '../rules/gcp-nist-800-53-rev4-2.2'
import Gcp_NIST_800_53_23 from '../rules/gcp-nist-800-53-rev4-2.3'

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

export interface NIST2xQueryResponse {
  querygcpDnsManagedZone?: QuerygcpDnsManagedZone[]
}

describe('GCP NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'gcp',
      entityName: 'NIST',
    })
  })

  describe('GCP NIST 2.1 DNS managed zone DNSSEC should be enabled', () => {
    const test33Rule = async (
      visibility: string,
      dnssecConfigState: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: NIST2xQueryResponse = {
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
        Gcp_NIST_800_53_21 as Rule,
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

  describe('GCP NIST 2.2 DNS managed zone DNSSEC key-signing keys should not use RSASHA1', () => {
    const test34Rule = async (
      visibility: string,
      keyType: string,
      algorithm: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: NIST2xQueryResponse = {
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
        Gcp_NIST_800_53_22 as Rule,
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

  describe('GCP NIST 2.3 DNS managed zone DNSSEC zone-signing keys should not use RSASHA1', () => {
    const test35Rule = async (
      visibility: string,
      keyType: string,
      algorithm: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: NIST2xQueryResponse = {
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
        Gcp_NIST_800_53_23 as Rule,
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
})
