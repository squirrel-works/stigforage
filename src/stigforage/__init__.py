"""stigforage: offline STIG checklist assessment toolkit (working name).

Changelog
---------
0.1.1  (roadmap stage 1, completed-but-pending-acceptance until the maintainer accepts it)
       Core model, CKLB read/write, structural validation, `info` and `validate` CLI.
       CKL read/write, XCCDF/SCAP/ZIP import, hardened stdlib XML parser, `convert` CLI.
       `validate --schema PATH`: stdlib subset JSON-Schema validator (schema.py) run against the
       DISA SV3 CKLB 1.0 schema. Generated CKLB is schema-valid: text fields are never null,
       no stig-level `version`, no STIGUuid/createdAt/updatedAt, real dc:identifier for
       reference_identifier, `unknown` severity, cklb_version "1.0".
"""

__version__ = "0.1.1"
