#!/usr/bin/env node

import { writeFile, readFile } from 'node:fs/promises'
import prettier from 'prettier'
import xml2js from 'xml2js'

const [, , REGISTRY_FILE] = process.argv
const OUTPUT_FILE = 'lib/shared/cwec.js'

/**
 * @typedef {{ ID: string; Name: string }} Weakness
 * @typedef {{Weaknesses: {Weakness: Array<Weakness>}}} Weaknesses
 */

const parser = new xml2js.Parser({
  explicitArray: false,
  mergeAttrs: true,
  explicitRoot: false,
})

const fileXML = await parser.parseStringPromise(
  await readFile(REGISTRY_FILE, 'utf-8')
)

const json = {
  weaknesses: fileXML.Weaknesses.Weakness.map(
    (/** @type {Weakness} */ weakness) => {
      return { id: `CWE-${weakness.ID}`, name: weakness.Name }
    }
  ),
}

await writeFile(
  OUTPUT_FILE,
  prettier.format(
    `export default /** @type {const} */ (${JSON.stringify(json)})`,
    {
      ...(await prettier.resolveConfig(OUTPUT_FILE)),
      filepath: OUTPUT_FILE,
    }
  )
)
