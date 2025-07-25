export default {
  license: [
    'Copyright (c) 2023, FIRST.ORG, INC.',
    'All rights reserved.',
    '',
    'Redistribution and use in source and binary forms, with or without modification, are permitted provided that the ',
    'following conditions are met:',
    '1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following ',
    '   disclaimer.',
    '2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the ',
    '   following disclaimer in the documentation and/or other materials provided with the distribution.',
    '3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote ',
    '   products derived from this software without specific prior written permission.',
    '',
    "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 'AS IS' AND ANY EXPRESS OR IMPLIED WARRANTIES, ",
    'INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE ',
    'DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, ',
    'SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR ',
    'SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, ',
    'WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE ',
    'OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.',
  ],

  $schema: 'https://json-schema.org/draft/2020-12/schema',
  title: 'JSON Schema for Common Vulnerability Scoring System version 4.0',
  $id: 'https://www.first.org/cvss/cvss-v4.0.json?20240216',
  type: 'object',
  definitions: {
    attackVectorType: {
      type: 'string',
      enum: ['NETWORK', 'ADJACENT', 'LOCAL', 'PHYSICAL'],
    },
    modifiedAttackVectorType: {
      type: 'string',
      enum: ['NETWORK', 'ADJACENT', 'LOCAL', 'PHYSICAL', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    attackComplexityType: {
      type: 'string',
      enum: ['HIGH', 'LOW'],
    },
    modifiedAttackComplexityType: {
      type: 'string',
      enum: ['HIGH', 'LOW', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    attackRequirementsType: {
      type: 'string',
      enum: ['NONE', 'PRESENT'],
    },
    modifiedAttackRequirementsType: {
      type: 'string',
      enum: ['NONE', 'PRESENT', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    privilegesRequiredType: {
      type: 'string',
      enum: ['HIGH', 'LOW', 'NONE'],
    },
    modifiedPrivilegesRequiredType: {
      type: 'string',
      enum: ['HIGH', 'LOW', 'NONE', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    userInteractionType: {
      type: 'string',
      enum: ['NONE', 'PASSIVE', 'ACTIVE'],
    },
    modifiedUserInteractionType: {
      type: 'string',
      enum: ['NONE', 'PASSIVE', 'ACTIVE', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    vulnCiaType: {
      type: 'string',
      enum: ['NONE', 'LOW', 'HIGH'],
    },
    modifiedVulnCiaType: {
      type: 'string',
      enum: ['NONE', 'LOW', 'HIGH', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    subCiaType: {
      type: 'string',
      enum: ['NONE', 'LOW', 'HIGH'],
    },
    modifiedSubCType: {
      type: 'string',
      enum: ['NEGLIGIBLE', 'LOW', 'HIGH', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    modifiedSubIaType: {
      type: 'string',
      enum: ['NEGLIGIBLE', 'LOW', 'HIGH', 'SAFETY', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    exploitMaturityType: {
      type: 'string',
      enum: ['UNREPORTED', 'PROOF_OF_CONCEPT', 'ATTACKED', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    ciaRequirementType: {
      type: 'string',
      enum: ['LOW', 'MEDIUM', 'HIGH', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    safetyType: {
      type: 'string',
      enum: ['NEGLIGIBLE', 'PRESENT', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    automatableType: {
      type: 'string',
      enum: ['NO', 'YES', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    recoveryType: {
      type: 'string',
      enum: ['AUTOMATIC', 'USER', 'IRRECOVERABLE', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    valueDensityType: {
      type: 'string',
      enum: ['DIFFUSE', 'CONCENTRATED', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    vulnerabilityResponseEffortType: {
      type: 'string',
      enum: ['LOW', 'MODERATE', 'HIGH', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    providerUrgencyType: {
      type: 'string',
      enum: ['CLEAR', 'GREEN', 'AMBER', 'RED', 'NOT_DEFINED'],
      default: 'NOT_DEFINED',
    },
    noneScoreType: {
      type: 'number',
      minimum: 0.0,
      maximum: 0.0,
    },
    lowScoreType: {
      type: 'number',
      minimum: 0.1,
      maximum: 3.9,
      multipleOf: 0.1,
    },
    mediumScoreType: {
      type: 'number',
      minimum: 4.0,
      maximum: 6.9,
      multipleOf: 0.1,
    },
    highScoreType: {
      type: 'number',
      minimum: 7.0,
      maximum: 8.9,
      multipleOf: 0.1,
    },
    criticalScoreType: {
      type: 'number',
      minimum: 9.0,
      maximum: 10,
      multipleOf: 0.1,
    },
    noneSeverityType: {
      const: 'NONE',
    },
    lowSeverityType: {
      const: 'LOW',
    },
    mediumSeverityType: {
      const: 'MEDIUM',
    },
    highSeverityType: {
      const: 'HIGH',
    },
    criticalSeverityType: {
      const: 'CRITICAL',
    },
  },
  properties: {
    version: {
      description: 'CVSS Version',
      type: 'string',
      enum: ['4.0'],
    },
    vectorString: {
      type: 'string',
      pattern:
        '^CVSS:4[.]0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]/VI:[HLN]/VA:[HLN]/SC:[HLN]/SI:[HLN]/SA:[HLN](/E:[XAPU])?(/CR:[XHML])?(/IR:[XHML])?(/AR:[XHML])?(/MAV:[XNALP])?(/MAC:[XLH])?(/MAT:[XNP])?(/MPR:[XNLH])?(/MUI:[XNPA])?(/MVC:[XNLH])?(/MVI:[XNLH])?(/MVA:[XNLH])?(/MSC:[XNLH])?(/MSI:[XNLHS])?(/MSA:[XNLHS])?(/S:[XNP])?(/AU:[XNY])?(/R:[XAUI])?(/V:[XDC])?(/RE:[XLMH])?(/U:(X|Clear|Green|Amber|Red))?$',
    },
    attackVector: { $ref: '#/definitions/attackVectorType' },
    attackComplexity: { $ref: '#/definitions/attackComplexityType' },
    attackRequirements: { $ref: '#/definitions/attackRequirementsType' },
    privilegesRequired: { $ref: '#/definitions/privilegesRequiredType' },
    userInteraction: { $ref: '#/definitions/userInteractionType' },
    vulnConfidentialityImpact: { $ref: '#/definitions/vulnCiaType' },
    vulnIntegrityImpact: { $ref: '#/definitions/vulnCiaType' },
    vulnAvailabilityImpact: { $ref: '#/definitions/vulnCiaType' },
    subConfidentialityImpact: { $ref: '#/definitions/subCiaType' },
    subIntegrityImpact: { $ref: '#/definitions/subCiaType' },
    subAvailabilityImpact: { $ref: '#/definitions/subCiaType' },
    exploitMaturity: { $ref: '#/definitions/exploitMaturityType' },
    confidentialityRequirement: { $ref: '#/definitions/ciaRequirementType' },
    integrityRequirement: { $ref: '#/definitions/ciaRequirementType' },
    availabilityRequirement: { $ref: '#/definitions/ciaRequirementType' },
    modifiedAttackVector: { $ref: '#/definitions/modifiedAttackVectorType' },
    modifiedAttackComplexity: {
      $ref: '#/definitions/modifiedAttackComplexityType',
    },
    modifiedAttackRequirements: {
      $ref: '#/definitions/modifiedAttackRequirementsType',
    },
    modifiedPrivilegesRequired: {
      $ref: '#/definitions/modifiedPrivilegesRequiredType',
    },
    modifiedUserInteraction: {
      $ref: '#/definitions/modifiedUserInteractionType',
    },
    modifiedVulnConfidentialityImpact: {
      $ref: '#/definitions/modifiedVulnCiaType',
    },
    modifiedVulnIntegrityImpact: { $ref: '#/definitions/modifiedVulnCiaType' },
    modifiedVulnAvailabilityImpact: {
      $ref: '#/definitions/modifiedVulnCiaType',
    },
    modifiedSubConfidentialityImpact: {
      $ref: '#/definitions/modifiedSubCType',
    },
    modifiedSubIntegrityImpact: { $ref: '#/definitions/modifiedSubIaType' },
    modifiedSubAvailabilityImpact: { $ref: '#/definitions/modifiedSubIaType' },
    Safety: { $ref: '#/definitions/safetyType' },
    Automatable: { $ref: '#/definitions/automatableType' },
    Recovery: { $ref: '#/definitions/recoveryType' },
    valueDensity: { $ref: '#/definitions/valueDensityType' },
    vulnerabilityResponseEffort: {
      $ref: '#/definitions/vulnerabilityResponseEffortType',
    },
    providerUrgency: { $ref: '#/definitions/providerUrgencyType' },
  },
  allOf: [
    {
      anyOf: [
        {
          properties: {
            baseScore: {
              $ref: '#/definitions/noneScoreType',
            },
            baseSeverity: {
              $ref: '#/definitions/noneSeverityType',
            },
          },
        },
        {
          properties: {
            baseScore: {
              $ref: '#/definitions/lowScoreType',
            },
            baseSeverity: {
              $ref: '#/definitions/lowSeverityType',
            },
          },
        },
        {
          properties: {
            baseScore: {
              $ref: '#/definitions/mediumScoreType',
            },
            baseSeverity: {
              $ref: '#/definitions/mediumSeverityType',
            },
          },
        },
        {
          properties: {
            baseScore: {
              $ref: '#/definitions/highScoreType',
            },
            baseSeverity: {
              $ref: '#/definitions/highSeverityType',
            },
          },
        },
        {
          properties: {
            baseScore: {
              $ref: '#/definitions/criticalScoreType',
            },
            baseSeverity: {
              $ref: '#/definitions/criticalSeverityType',
            },
          },
        },
      ],
    },
    {
      anyOf: [
        {
          properties: {
            threatScore: {
              $ref: '#/definitions/noneScoreType',
            },
            threatSeverity: {
              $ref: '#/definitions/noneSeverityType',
            },
          },
        },
        {
          properties: {
            threatScore: {
              $ref: '#/definitions/lowScoreType',
            },
            threatSeverity: {
              $ref: '#/definitions/lowSeverityType',
            },
          },
        },
        {
          properties: {
            threatScore: {
              $ref: '#/definitions/mediumScoreType',
            },
            threatSeverity: {
              $ref: '#/definitions/mediumSeverityType',
            },
          },
        },
        {
          properties: {
            threatScore: {
              $ref: '#/definitions/highScoreType',
            },
            threatSeverity: {
              $ref: '#/definitions/highSeverityType',
            },
          },
        },
        {
          properties: {
            threatScore: {
              $ref: '#/definitions/criticalScoreType',
            },
            threatSeverity: {
              $ref: '#/definitions/criticalSeverityType',
            },
          },
        },
      ],
    },
    {
      anyOf: [
        {
          properties: {
            environmentalScore: {
              $ref: '#/definitions/noneScoreType',
            },
            environmentalSeverity: {
              $ref: '#/definitions/noneSeverityType',
            },
          },
        },
        {
          properties: {
            environmentalScore: {
              $ref: '#/definitions/lowScoreType',
            },
            environmentalSeverity: {
              $ref: '#/definitions/lowSeverityType',
            },
          },
        },
        {
          properties: {
            environmentalScore: {
              $ref: '#/definitions/mediumScoreType',
            },
            environmentalSeverity: {
              $ref: '#/definitions/mediumSeverityType',
            },
          },
        },
        {
          properties: {
            environmentalScore: {
              $ref: '#/definitions/highScoreType',
            },
            environmentalSeverity: {
              $ref: '#/definitions/highSeverityType',
            },
          },
        },
        {
          properties: {
            environmentalScore: {
              $ref: '#/definitions/criticalScoreType',
            },
            environmentalSeverity: {
              $ref: '#/definitions/criticalSeverityType',
            },
          },
        },
      ],
    },
  ],
  required: ['version', 'vectorString', 'baseScore', 'baseSeverity'],
}
