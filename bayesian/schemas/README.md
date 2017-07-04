# Schemas for API server

This directory contains versioned schemas for the core Bayesian API
endpoints, written in JSL format.

 * [JSON Schema](http://json-schema.org/documentation.html)
 * [JSL](https://jsl.readthedocs.io/en/latest/tutorial.html)

The numbering of the schemas uses Snowplow's SchemaVer concept [1], which says
that, given a version number MODEL-REVISION-ADDITION, increment the:

* MODEL when you make a breaking schema change which will prevent validation
  of any historical data (e.g. a new mandatory field has been added)
* REVISION when you make a schema change which may prevent validation of
  some historical data (e.g. only new optional fields have been added, but they
  may conflict with fields in some historical data)
* ADDITION when you make a schema change that is compatible with all
  historical data (i.e. only new optional fields have been added, and they
  cannot conflict with fields in any historical data)

For information on how to properly create schemas and what top-level variables
need to be provided in the schema file, see `lib/f8a_worker/workers/schemas/README.md`.

TODO: Unify schema readme files for lib and server
TODO: Hyperlink to detailed component scanner schemas
TODO: Making the analyses self-describing

[1] http://snowplowanalytics.com/blog/2014/05/13/introducing-schemaver-for-semantic-versioning-of-schemas/
