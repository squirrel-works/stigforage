"""stigforage: offline STIG checklist assessment toolkit (working name).

Changelog
---------
0.1.1  (roadmap stage 1, accepted by the maintainer)
       Core model, CKLB read/write, structural validation, `info` and `validate` CLI.
       CKL read/write, XCCDF/SCAP/ZIP import, hardened stdlib XML parser, `convert` CLI.
       `validate --schema PATH`: stdlib subset JSON-Schema validator (schema.py) run against the
       DISA SV3 CKLB 1.0 schema. Generated CKLB is schema-valid: text fields are never null,
       no stig-level `version`, no STIGUuid/createdAt/updatedAt, real dc:identifier for
       reference_identifier, `unknown` severity, cklb_version "1.0".
0.2.2  (roadmap stage 2, in progress)
       Unit 1: `diff` command and diff.match_rules (shared matching policy, ADR 0002).
       Defect fix from accepted 0.1.1, included in this stage with maintainer approval: the
       `convert` dry run reported "would write" and exited 0 where --apply then failed. It now
       refuses what --apply refuses (OUTPUT exists without --force, OUTPUT is a directory,
       missing directory) with exit 2, and logs .ckl export warnings. fsio.check_write_target
       holds those checks for both paths.
"""

__version__ = "0.1.1"
