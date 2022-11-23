/* eslint-disable max-len */
import cuid from 'cuid'
import { Rule, Result, Engine } from '@cloudgraph/sdk'
import 'jest'

import Gcp_CIS_130_71 from '../rules/gcp-cis-1.3.0-7.1'
import Gcp_CIS_130_72 from '../rules/gcp-cis-1.3.0-7.2'
import Gcp_CIS_130_73 from '../rules/gcp-cis-1.3.0-7.3'
import { initRuleEngine } from '../../../utils/test'

export interface Access {
  role: string
}

export interface DefaultEncryptionConfiguration {
  kmsKeyName: string | null
}

export interface Tables {
  encryptionConfigurationKmsKeyName: string | null
}

export interface QuerygcpBigQueryDataset {
  id: string
  access?: Access[]
  tables?: Tables[]
  defaultEncryptionConfiguration?: DefaultEncryptionConfiguration
}

export interface CIS7xQueryResponse {
  querygcpBigQueryDataset?: QuerygcpBigQueryDataset[]
}

describe('CIS Google Cloud Platform Foundations: 1.3.0', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = initRuleEngine('gcp', 'CIS')
  })

  describe('GCP CIS 7.1 Ensure that BigQuery datasets are not anonymously or publicly accessible', () => {
    const testRule = async (
      roleName: string,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS7xQueryResponse = {
        querygcpBigQueryDataset: [
          {
            id: cuid(),
            access: [
              {
                role: roleName
              }
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_71 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a datasets that are not anonymously or publicly accessible', async () => {
      await testRule('writter', Result.PASS)
    })

    test('Security Issue when there is an inbound rule with a datasets that have granted access to "allUsers" role.', async () => {
      await testRule('allUsers', Result.FAIL)
    })

    test('Security Issue when there is an inbound rule with a datasets that have granted access to "allAuthenticatedUsers" role.', async () => {
      await testRule('allAuthenticatedUsers', Result.FAIL)
    })
  })

  describe('GCP CIS 7.2 Ensure that all BigQuery Tables are encrypted with Customer-managed encryption key (CMEK)', () => {
    const testRule = async (
      kmsKeyName: string | null,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS7xQueryResponse = {
        querygcpBigQueryDataset: [
          {
            id: cuid(),
            tables: [
              {
                encryptionConfigurationKmsKeyName: kmsKeyName
              }
            ],
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_72 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a Customer-managed encryption key.', async () => {
      await testRule('encryption-key', Result.PASS)
    })

    test('Security Issue when there is an inbound rule without a Customer-managed encryption key.', async () => {
      await testRule('', Result.FAIL)
    })
  })

  describe('GCP CIS 7.3 Ensure that a Default Customer-managed encryption key (CMEK) is specified for all BigQuery Data Sets', () => {
    const testRule = async (
      kmsKeyName: string | null,
      expectedResult: Result
    ): Promise<void> => {
      // Arrange
      const data: CIS7xQueryResponse = {
        querygcpBigQueryDataset: [
          {
            id: cuid(),
            defaultEncryptionConfiguration:
            {
              kmsKeyName
            }
          },
        ],
      }

      // Act
      const [processedRule] = await rulesEngine.processRule(
        Gcp_CIS_130_73 as Rule,
        { ...data }
      )

      // Asserts
      expect(processedRule.result).toBe(expectedResult)
    }

    test('No Security Issue when there is an inbound rule with a default Customer-managed encryption key.', async () => {
      await testRule('default-encryption-key', Result.PASS)
    })

    test('Security Issue when there is an inbound rule without a default Customer-managed encryption key.', async () => {
      await testRule('', Result.FAIL)
    })
  })
})
