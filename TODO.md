# simple-sandbox TODO

## Done
- [x] Mac seatbelt + Podman mechanisms, krun stub
- [x] Path deps → private siblings
- [x] Mac allowlist: fail closed (localhost only, no general outbound)
- [x] Persist policy.yaml next to profile.sb so `exec` applies rlimits/proxy env

## Open
- [ ] Podman allowlist still uses bridge + HTTP(S)_PROXY honor system — fail closed (`--network none` + sidecar)
- [ ] Keep allowlist proxy alive after `ssbx create` (dropped handle today)
- [ ] `policy set` must regenerate seatbelt / recreate container
- [ ] Seatbelt `subpath` prefix escapes
- [ ] Podman hardening (`--cap-drop`, no-new-privs, non-root)
- [ ] Real host capacity probe (limited-core preflight is static)
- [ ] Linux-on-Linux + bubblewrap; libkrun
- [ ] Wire or drop unused `ControlChannel` / `simple_network`
