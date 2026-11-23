# shuttle

shuttle carries a proved caller identity into the two places handlers read authority from: the sealed [loom](https://github.com/bbmumford/loom) principal (subject, partition, grants) and the [weft](https://github.com/bbmumford/weft) carrier, so a handler reached over HTTP and one reached over the mesh see the same identity from the same place. It carries identity only, not jobs or tasks.

- **`Ingress`** (HTTP): turns what your `CredentialReader` proved into the sealed principal and stamps weft from that seal. It attaches and does not gate: a request with no credential, an incomplete one, or a non-canonical grant passes through with nothing stamped, and the handler's policy denies it.
- **`WeftStamping`** (mesh): wraps a loom `ports.AuthValidator` and stamps weft from the principal loom sealed on the receive path, and only from it.
- **`MembershipAdmitter`**: decides whether a principal arriving from another node may act in the partition it claims, through a `MembershipFunc` you supply; it refuses with `ErrNoSubject`, `ErrNoPartition`, `ErrNoMembership`, `ErrNotMember` or `ErrMembershipUnread`.
- **`DirectCapabilities(realm)`**: a loom `scope.Authorizer` that confers a capability of one realm only when the principal's own grants, read as [warrant](https://github.com/bbmumford/warrant) capabilities of that realm, allow it; grants and requirements outside the realm never count.

## Use

```sh
go get github.com/bbmumford/shuttle
```

```go
mw := shuttle.Ingress(shuttle.IngressConfig{
	Reader: shuttle.CredentialReaderFunc(func(r *http.Request) (shuttle.ProvedIdentity, bool) {
		// verify the request's credential, then:
		return shuttle.ProvedIdentity{Subject: sub, Partition: part, Grants: grants}, true
	}), // AuthType defaults to weft's session label; Seal can add your own carrier
})
handler = mw(handler)

validator = shuttle.WeftStamping(validator) // the loom RPC server's validator
```

## Dependencies

- `github.com/bbmumford/loom` (`ports`, `pkg/rpc/scope`): the sealed
  principal, the `AuthValidator` seam and the `scope.Authorizer` it implements.
- `github.com/bbmumford/weft`: the identity carrier it stamps.
- `github.com/bbmumford/warrant`: grants read as capabilities.
- No external module. `go.mod` replaces loom, warrant and weft with sibling
  checkouts, so a build outside a workspace needs them checked out beside it.

## Used by

Importers in the ORBTR estate:

- `github.com/ORBTR/Library/endpoint` (the endpoint spine),
  `authadapters`, `domain/identityhost`, `sessioncred` (and `rpcstore`) and
  `tokencred`.
- The AI endpoints `app`, `console`, `fleet`, `manage` and `studio.orbtr.ai`,
  and `github.com/ORBTR/node.orbtr.io`.
- Tests only: packages of `github.com/ORBTR/cortex` and
  `github.com/ORBTR/constellation`, and the `api`, `node`, `runtime` and
  `worker.orbtr.ai` and `app.orbtr.io` endpoints.

## Platforms and build

Pure Go, no cgo and no build tags. The module's `go` directive is 1.25.0.

## Licence

MIT. Copyright (c) 2026 Brandon Miller-Mumford. The full text is in
[LICENSE](LICENSE).

## Contributing

[AGENTS.md](AGENTS.md) holds the repository's two rules, for people and coding
agents alike: no temporary documents in the repository, and conventional commit
messages that stand on their own. [CLAUDE.md](CLAUDE.md) imports it for Claude
Code.
