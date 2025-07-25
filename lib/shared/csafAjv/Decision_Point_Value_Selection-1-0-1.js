export default {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://certcc.github.io/SSVC/data/schema/v1/Decision_Point_Value_Selection-1-0-1.schema.json',
  description:
    'This schema defines the structure for selecting SSVC Decision Points and their evaluated values for a given vulnerability. Each vulnerability can have multiple Decision Points, and each Decision Point can have multiple selected values when full certainty is not available.',
  $defs: {
    id: {
      type: 'string',
      description:
        'Identifier for the vulnerability that was evaluation, such as CVE, CERT/CC VU#, OSV id, Bugtraq, GHSA etc.',
      examples: ['CVE-1900-1234', 'VU#11111', 'GHSA-11a1-22b2-33c3'],
      minLength: 1,
    },
    role: {
      type: 'string',
      description:
        'The role of the stakeholder performing the evaluation (e.g., Supplier, Deployer, Coordinator). See SSVC documentation for a currently identified list: https://certcc.github.io/SSVC/topics/enumerating_stakeholders/',
      examples: ['Supplier', 'Deployer', 'Coordinator'],
      minLength: 1,
    },
    timestamp: {
      description:
        'Date and time when the evaluation of the Vulnerability was performed according to RFC 3339, section 5.6.',
      type: 'string',
      format: 'date-time',
    },
    SsvcdecisionpointselectionSchema: {
      description:
        'A down-selection of SSVC Decision Points that represent an evaluation at a specific time of a Vulnerability evaluation.',
      properties: {
        name: {
          $ref: 'https://certcc.github.io/SSVC/data/schema/v1/Decision_Point-1-0-1.schema.json#/$defs/decision_point/properties/name',
        },
        namespace: {
          $ref: 'https://certcc.github.io/SSVC/data/schema/v1/Decision_Point-1-0-1.schema.json#/$defs/decision_point/properties/namespace',
        },
        values: {
          description:
            'One or more Decision Point Values that were selected for this Decision Point. If the evaluation is uncertain, multiple values may be listed to reflect the potential range of possibilities.',
          title: 'values',
          type: 'array',
          minItems: 1,
          items: {
            $ref: 'https://certcc.github.io/SSVC/data/schema/v1/Decision_Point-1-0-1.schema.json#/$defs/decision_point_value/properties/name',
          },
        },
        version: {
          $ref: 'https://certcc.github.io/SSVC/data/schema/v1/Decision_Point-1-0-1.schema.json#/$defs/decision_point/properties/version',
        },
      },
      type: 'object',
      required: ['name', 'namespace', 'values', 'version'],
      additionalProperties: false,
    },
  },
  properties: {
    id: {
      $ref: '#/$defs/id',
    },
    role: {
      $ref: '#/$defs/role',
    },
    schemaVersion: {
      $ref: 'https://certcc.github.io/SSVC/data/schema/v1/Decision_Point-1-0-1.schema.json#/$defs/schemaVersion',
    },
    timestamp: {
      $ref: '#/$defs/timestamp',
    },
    selections: {
      description:
        'An array of Decision Points and their selected values for the identified Vulnerability.  If a clear evaluation is uncertain, multiple values may be listed for a Decision Point instead of waiting for perfect clarity.',
      title: 'selections',
      type: 'array',
      minItems: 1,
      items: {
        $ref: '#/$defs/SsvcdecisionpointselectionSchema',
      },
    },
  },
  type: 'object',
  required: ['selections', 'id', 'timestamp', 'schemaVersion'],
  additionalProperties: false,
}
