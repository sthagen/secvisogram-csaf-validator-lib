import assert from 'node:assert'
import { mandatoryTest_6_1_4 } from '../../csaf_2_1/mandatoryTests/mandatoryTest_6_1_4.js'

describe('mandatoryTest_6_1_4', function () {
  it('only runs on relevant documents', function () {
    assert.equal(mandatoryTest_6_1_4({ document: 'mydoc' }).isValid, true)
  })
})
