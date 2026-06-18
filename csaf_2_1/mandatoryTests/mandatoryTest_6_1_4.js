import { Ajv } from 'ajv/dist/jtd.js'
import {
  collectGroupIdsFromProductTree,
  findMissingDefinitions,
} from './shared/docProductUtils.js'

const ajv = new Ajv()

const groupIdsSchema = /** @type {const} */ ({
  additionalProperties: true,
  optionalProperties: {
    group_ids: { elements: { type: 'string' } },
  },
})

const vulnerabilitySchema = /** @type {const} */ ({
  additionalProperties: true,
  optionalProperties: {
    first_known_exploitation_dates: { elements: groupIdsSchema },
    flags: { elements: groupIdsSchema },
    ids: { elements: groupIdsSchema },
    involvements: { elements: groupIdsSchema },
    notes: { elements: groupIdsSchema },
    remediations: { elements: groupIdsSchema },
    threats: { elements: groupIdsSchema },
  },
})

/*
  This is the jtd schema that needs to match the input document so that the
  test is activated. If this schema doesn't match it normally means that the input
  document does not validate against the csaf json schema or optional fields that
  the test checks are not present.
 */
const inputSchema = /** @type {const} */ ({
  additionalProperties: true,
  optionalProperties: {
    document: {
      additionalProperties: true,
      optionalProperties: {
        notes: { elements: groupIdsSchema },
      },
    },
    vulnerabilities: { elements: vulnerabilitySchema },
  },
})

const validateInput = ajv.compile(inputSchema)

/**
 * @typedef {import('ajv/dist/core.js').JTDDataType<typeof vulnerabilitySchema>} Vulnerability
 * @typedef {import('ajv/dist/core.js').JTDDataType<typeof inputSchema>} InputSchema
 * @typedef {{id: string, instancePath: string}} GroupId
 */

/**
 * This implements the mandatory test 6.1.4 of the CSAF 2.1 standard.
 *
 * @param {unknown} doc
 */
export function mandatoryTest_6_1_4(doc) {
  const ctx = {
    errors:
      /** @type {Array<{ instancePath: string; message: string }>} */ ([]),
    isValid: true,
  }

  if (!validateInput(doc)) {
    return ctx
  }

  const groupIds = collectGroupIdsFromProductTree(/** @type {any} */ (doc))
  const groupIdRefs = collectGroupIds(doc)
  const missingGroupDefinitions =
    /** @type {{id: string, instancePath: string}[]} */ (
      findMissingDefinitions(groupIds, groupIdRefs)
    )
  if (missingGroupDefinitions.length > 0) {
    ctx.isValid = false
    missingGroupDefinitions.forEach(
      (
        /** @type {{id: string, instancePath: string}} */ missingGroupDefinition
      ) => {
        ctx.errors.push({
          message: 'definition of group id missing',
          instancePath: missingGroupDefinition.instancePath,
        })
      }
    )
  }

  return ctx
}

/**
 * This method collects references to group ids and corresponding instancePaths in the given document.
 * @param {InputSchema} doc
 * @returns {GroupId[]}
 */
function collectGroupIds(doc) {
  const entries = /** @type {GroupId[]} */ ([])

  doc.document?.notes?.forEach((documentNote, documentNoteIndex) => {
    collectRefsInGroupIds(
      documentNote.group_ids,
      `/document/notes/${documentNoteIndex}/group_ids`,
      entries
    )
  })

  doc.vulnerabilities?.forEach((vulnerability, vulnerabilityIndex) => {
    collectGroupRefsInFirstKnownExploitationDates(
      `/vulnerabilities/${vulnerabilityIndex}/first_known_exploitation_dates`,
      vulnerability,
      entries
    )
    collectGroupRefsInFlags(
      `/vulnerabilities/${vulnerabilityIndex}/flags`,
      vulnerability,
      entries
    )
    collectGroupRefsInIds(
      `/vulnerabilities/${vulnerabilityIndex}/ids`,
      vulnerability,
      entries
    )
    collectGroupRefsInInvolvements(
      `/vulnerabilities/${vulnerabilityIndex}/involvements`,
      vulnerability,
      entries
    )
    collectGroupRefsInNotes(
      `/vulnerabilities/${vulnerabilityIndex}/notes`,
      vulnerability,
      entries
    )
    collectGroupRefsInRemediations(
      `/vulnerabilities/${vulnerabilityIndex}/remediations`,
      vulnerability,
      entries
    )
    collectGroupRefsInThreats(
      `/vulnerabilities/${vulnerabilityIndex}/threats`,
      vulnerability,
      entries
    )
  })

  return entries
}

/**
 * @param {string[] | undefined} groupIds
 * @param {string} instancePath
 * @param {GroupId[]} entries
 */
const collectRefsInGroupIds = (groupIds, instancePath, entries) => {
  groupIds?.forEach((groupId, groupIdIndex) => {
    if (groupId) {
      entries.push({
        id: groupId,
        instancePath: `${instancePath}/${groupIdIndex}`,
      })
    }
  })
}

/**
 * @param {string} instancePath
 * @param {Vulnerability} vulnerability
 * @param {GroupId[]} entries
 */
const collectGroupRefsInFirstKnownExploitationDates = (
  instancePath,
  vulnerability,
  entries
) => {
  vulnerability.first_known_exploitation_dates?.forEach(
    (firstKnownExploitationDate, firstKnownExploitationDateIndex) => {
      collectRefsInGroupIds(
        firstKnownExploitationDate.group_ids,
        `${instancePath}/${firstKnownExploitationDateIndex}/group_ids`,
        entries
      )
    }
  )
}

/**
 * @param {string} instancePath
 * @param {Vulnerability} vulnerability
 * @param {GroupId[]} entries
 */
const collectGroupRefsInFlags = (instancePath, vulnerability, entries) => {
  vulnerability.flags?.forEach((flag, flagIndex) => {
    collectRefsInGroupIds(
      flag.group_ids,
      `${instancePath}/${flagIndex}/group_ids`,
      entries
    )
  })
}

/**
 * @param {string} instancePath
 * @param {Vulnerability} vulnerability
 * @param {GroupId[]} entries
 */
const collectGroupRefsInIds = (instancePath, vulnerability, entries) => {
  vulnerability.ids?.forEach((id, idIndex) => {
    collectRefsInGroupIds(
      id.group_ids,
      `${instancePath}/${idIndex}/group_ids`,
      entries
    )
  })
}

/**
 * @param {string} instancePath
 * @param {Vulnerability} vulnerability
 * @param {GroupId[]} entries
 */
const collectGroupRefsInInvolvements = (
  instancePath,
  vulnerability,
  entries
) => {
  vulnerability.involvements?.forEach((involvement, involvementIndex) => {
    collectRefsInGroupIds(
      involvement.group_ids,
      `${instancePath}/${involvementIndex}/group_ids`,
      entries
    )
  })
}

/**
 * @param {string} instancePath
 * @param {Vulnerability} vulnerability
 * @param {GroupId[]} entries
 */
const collectGroupRefsInNotes = (instancePath, vulnerability, entries) => {
  vulnerability.notes?.forEach((note, noteIndex) => {
    collectRefsInGroupIds(
      note.group_ids,
      `${instancePath}/${noteIndex}/group_ids`,
      entries
    )
  })
}

/**
 * @param {string} instancePath
 * @param {Vulnerability} vulnerability
 * @param {GroupId[]} entries
 */
const collectGroupRefsInRemediations = (
  instancePath,
  vulnerability,
  entries
) => {
  vulnerability.remediations?.forEach((remediation, remediationIndex) => {
    collectRefsInGroupIds(
      remediation.group_ids,
      `${instancePath}/${remediationIndex}/group_ids`,
      entries
    )
  })
}

/**
 * @param {string} instancePath
 * @param {Vulnerability} vulnerability
 * @param {GroupId[]} entries
 */
const collectGroupRefsInThreats = (instancePath, vulnerability, entries) => {
  vulnerability.threats?.forEach((threat, threatIndex) => {
    collectRefsInGroupIds(
      threat.group_ids,
      `${instancePath}/${threatIndex}/group_ids`,
      entries
    )
  })
}
