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
0.2.2  (roadmap stage 2, accepted by the maintainer)
       Unit 1: `diff` command and diff.match_rules (shared matching policy, ADR 0002).
       Defect fix from accepted 0.1.1, included in this stage with maintainer approval: the
       `convert` dry run reported "would write" and exited 0 where --apply then failed. It now
       refuses what --apply refuses (OUTPUT exists without --force, OUTPUT is a directory,
       missing directory) with exit 2, and logs .ckl export warnings. fsio.check_write_target
       holds those checks for both paths.
       Unit 2: `merge SOURCE TARGET -o OUTPUT` (merge.py) carries review units between
       checklists of the same release (ADR 0002 addendum). STIG pairing moved to
       diff.pair_stigs; convert and merge share the output checks and dry-run path.
       Unit 3: `upgrade OLD NEW_BENCHMARK -o OUTPUT` (upgrade.py) carries reviews onto a new
       release, downgrading to not_reviewed with a note where the check text changed
       (--keep-status-on-change to skip). Reuses merge's review unit and release test.
0.3.3  (roadmap stage 3, in progress)
       Unit 1: `import-results CHECKLIST RESULTS... -o OUTPUT` (results.py) applies XCCDF
       results and ARF (SCC, Evaluate-STIG, OpenSCAP, STIG Manager) per ADR 0003: pass, fail
       and notapplicable imported, others counted; checklist wins unless --prefer results;
       other releases refused, other hosts refused unless --allow-host-mismatch.
       Unit 2: InSpec / Heimdall HDF `.json` results (hdf.py). Control status follows
       Heimdall's order, except waived controls are counted, not imported. HDF names no
       benchmark or host, so scans pair with the checklist STIG holding their V-numbers;
       release from a STIGRef tag or a vNrN profile title; overlay data from the base control.
       Any scan of unknown release warns when matched rule revisions differ (drift).
"""

__version__ = "0.2.2"
