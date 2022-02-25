import CloudGraph, { Rule, Result, Engine } from '@cloudgraph/sdk'


describe('AWS NIST 800-53: Rev. 4', () => {
  let rulesEngine: Engine
  beforeAll(() => {
    rulesEngine = new CloudGraph.RulesEngine({
      providerName: 'aws',
      entityName: 'NIST',
    })
  })

  // TODO: Change once we have real checks
  describe("Dummy Check", () => {
    test('Dummy Test', async () => {
      expect('PASS').toBe(Result.PASS)
    })
  })
})
