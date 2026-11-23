# XDR → ISOC staged migration: preflight and cutover runbook

**Status:** PREPARATION ONLY. **Owner approval required before any production DNS, deployment, GitHub repository transfer, repository deletion, release or auth/permission changes.**

**Tracked by:** [xdr-labs/xdr-labs-portal#62](https://github.com/xdr-labs/xdr-labs-portal/issues/62)  
**Baseline:** 2026-11-23 (Asia/Seoul)  
**Source organization:** https://github.com/xdr-labs  
**Target organization:** https://github.com/isoc-labs (not created publicly or not yet accessible as of baseline)  
**Current portal:** https://xdr.ooo (HTTP 200)  
**Target portal:** https://isoc.ooo (Cloudflare nameservers present; apex has no A/AAAA/CNAME and does not resolve)  
**Existing separately migrated service:** https://rfp.isoc.ooo (HTTP 200)

## Decision: copy for preview, Transfer for final ownership

Preserve existing customer-facing installations and sites until the destination is independently validated.

1. Create target GitHub organization \`isoc-labs\`, enable appropriate repository-create/transfer authorization, and connect the GitHub app.
2. Use a **temporary name** such as \`isoc-labs/xdr-labs-portal-migration-preview\` for a mirrored preview checkout. Never mirror into the final repository name if a **GitHub Transfer** will later be used; the target name conflict blocks transfer.
3. Keep the source repositories and current Mintlify/Nginx/other deployments active.
4. Migrate the portal to a separate destination Mintlify project and verify DNS/TLS and full site behavior on the target.
5. Perform service-by-service app/docs migration with dual-run functional and E2E testing; update origins/callback URLs and deployment configuration where relevant.
6. When development PRs are settled, transfer final repositories **one by one** to preserve Issues, PRs, releases, wiki, stars and Git history. Revalidate GitHub Actions and credentials, webhook integrations, Releases, LFS, GHCR, branch protection, deployment permissions and GitHub Pages.
7. After an agreed observation period, retain legacy URL redirects and only then consider retirement/deletion under a separate owner approval.

GitHub Transfer automatically redirects previous GitHub repository URLs, but old GitHub Pages URLs are **not** automatically redirected. Creating a new repository at the old name can destroy the redirect. Do not assume installer-specific raw URLs or asset endpoints are compatible without testing. GitHub's [official Transfer documentation](https://docs.github.com/en/repositories/creating-and-managing-repositories/transferring-a-repository) is the reference.

## Verified inventory (15 repositories; default branch HEAD pinned during audit)

| Repository | HEAD prefix | Strict scan matching lines | Primary migration concern |
| --- | --- | ---: | --- |
| xdr-labs-portal | 30cd0aa | 150 | Mintlify navigation, canonical, release downloads, active Suricata PRs |
| openxdr-kvm-installer-docs | 62f6cc7 | 41 | Mintlify domain and installation guide links |
| detection-scenario-platform-docs | 437647f | 25 | Mintlify domain links |
| xdr-labs-dp-os-upgrade-docs | 892cc37 | 18 | Mintlify domain links |
| stellar-alert-case-relay-docs | 2fb614c | 13 | Mintlify domain links |
| parser-studio-docs | b5e0733 | 125 | Mintlify, live workflow verifier and examples |
| Stellar-appliance-cli | b7b694a | 6 | Public installation and repository URL references |
| stellar-data-exporter | ce758bb | 15 | Published package metadata and release verifier |
| Stellar-Case-Alert-to-Sylog | ad9656b | 9 | Application output/reference URLs |
| OpenXDR-KVM-Installer | 83dad2b | 23 | Executable installation scripts and immutable source URLs |
| ubuntu-mirror-automation | 129eb03 | 52 | Bootstrap and Phase 2 deployment/release sources |
| xdr-lab-appliance | bf2d70e | 91 | Scripts and nested detection scenario code |
| xdr-poc-script | 024817b | 60 | Installer script and nested DSP code |
| detection-scenario-platform | f56127c | 45 | Shared DSP code/docs/test references |
| parser-studio | af7de35 | 186 | Nginx TLS, app host, API/CORS/origins, deployment scripts and active PRs |

The read-only strict scanner found **859 matching source lines** across 15 default-branch checkouts; **247 lines** were classified as operational code/config. An earlier broader exploratory scan counted 891 lines with a different matching rule. Reference counts do not equal changes needed. Some occurrences are historical/fixture text, governance metadata, or intentional compatibility links; these must not be blindly replaced.

For a deterministic local recheck after cloning the public source repositories into a single directory:

\`\`\`sh
python3 tools/audit_xdr_isoc_refs.py --root /path/to/source-repo-checkouts --output /tmp/xdr-isoc-audit.json
\`\`\`

The tool is read-only with respect to source checkouts; it writes only the explicitly requested JSON report.

## Domain mapping to validate; not live target records

| Existing | Intended target | Readiness baseline |
| --- | --- | --- |
| xdr.ooo | isoc.ooo | Existing HTTP 200; target DNS missing |
| rfp.xdr.ooo | rfp.isoc.ooo | Both HTTP 200; keep legacy during dual-run |
| dpos.xdr.ooo | dpos.isoc.ooo | Existing HTTP 200; target not validated |
| dsp.xdr.ooo | dsp.isoc.ooo | Existing HTTP 200; target not validated |
| kvm.xdr.ooo | kvm.isoc.ooo | Existing HTTP 200; target not validated |
| stellar-relay.xdr.ooo | stellar-relay.isoc.ooo | Existing HTTP 200; target not validated |
| parser.xdr.ooo | parser.isoc.ooo | Existing HTTP 200; target not validated |
| app.parser.xdr.ooo | app.parser.isoc.ooo | Existing HTTP 200; target not validated |

The \`datarelay-labs\` organization and \`*.datarelay.run\` are **out of scope**. Prefer keeping the existing repository names on transfer (including names with an xdr prefix) initially; separate rename decisions are higher risk and can be made after the domain/owner cutover.

## Required cutover checks, in order

### Gate A — owner-only setup
- [ ] Create \`isoc-labs\` GitHub Organization and verify direct membership/ownership.
- [ ] Install the GitHub ChatGPT App to \`isoc-labs\` with the necessary repository access (not credentials pasted in chat).
- [ ] Prepare separate Mintlify project GitHub integration and destination domain configuration, with the exact DNS record values produced by Mintlify. Do **not** guess an IP or point \`isoc.ooo\` to the old origin.
- [ ] Confirm hosting providers and Cloudflare account have the expected domain permissions. Do not share tokens.

### Gate B — portal pilot (no production change)
- [ ] Mirror portal into a **temporary preview name**. Pin and compare source HEAD, branches and tags. Review workflows before enabling any Actions in preview.
- [ ] Reconnect Mintlify to preview source; validate EN/KR, navigation, favicon/logo, 404 behavior, canonical/SEO, \`/downloads\` and release assets, links and external apps.
- [ ] Validate TLS and DNS, then bind \`isoc.ooo\` only to the new deployment. Keep \`xdr.ooo\` serving the original site.
- [ ] Verify that source updates and preview updates do not silently diverge; determine final authoritative repo before accepting contributions.

### Gate C — documentation and CLI tooling
- [ ] Create and verify documentation destinations separately for kvm, dpos, dsp, stellar-relay and parser.
- [ ] Test exact existing and target installer commands, pinned release SHA, checksums and installer runtime behavior. Do not bulk-rewrite URLs in shell/production files.
- [ ] Check relative and absolute links, GHCR/package references, repo tags, raw GitHub content, permissions, issues, existing PRs, Webhooks and CI on the new org.

### Gate D — application and GitHub ownership
- [ ] Set up \`app.parser.isoc.ooo\` with its own valid certificate, Nginx config and app origin policies; keep old application live; run full browser user E2E on the deployment candidate.
- [ ] Settle/rebase open PRs before final owner transfer. As of baseline \`xdr-labs/parser-studio#316\` and \`xdr-labs/xdr-labs-portal#60\` are open.
- [ ] Transfer one final repository at a time, do not replace it with a Git clone that loses Issue/PR history.
- [ ] After transfer, update local Git remotes, Mintlify integration, CODEOWNERS, GitHub App installation, Actions secrets/variables, branch rules and deploy identity. Verify CI, artifacts, signatures and downloads.
- [ ] Validate old repository redirects without recreating old names.

### Gate E — stabilization, rollback, retirement
- [ ] Compare the old and new sites before and after DNS changes. Confirm DNS/TLS, HTTP 200, EN/KR and downloadable assets; capture timing, errors, and E2E evidence.
- [ ] Preserve legacy domains and repository redirects for compatibility, especially existing installation instructions.
- [ ] On failed validation, restore the previous hostname mapping/deployment and retain original sources. Do not delete originals during rollback.
- [ ] Retire original resources **only with separate approval**, after traffic and dependency monitoring confirms it is safe. Prefer long-lived HTTP 301 redirects for public URLs.

## Non-goals for this preparation change

No live website modifications, no DNS writes, no GitHub Organization/repository creation, no repository transfer, no changes to active application/parser logic, no release or deployment. The portal's existing production README/SEO/download links intentionally continue to point to live xdr resources until the destination is ready.
