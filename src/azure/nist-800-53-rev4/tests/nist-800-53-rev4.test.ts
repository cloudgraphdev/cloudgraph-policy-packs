import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'

describe('Azure NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'azure',
      entityName: 'NIST',
    })
  })

  // TODO: Change once we have real checks
  describe('Dummy Check', () => {
    test('Dummy Test', async () => {
      expect('PASS').toBe(Result.PASS)
    })
  })
})
