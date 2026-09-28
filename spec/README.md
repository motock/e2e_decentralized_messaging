# Protocol specification

Versioned, published protobuf wire-format and protocol specification (PLAN.md §5, "Protocol
portability").

- [`v0.md`](v0.md) — wire-format spec v0 (draft, pending sign-off per its §8).
- [`proto/v0/`](proto/v0/) — the protobuf schemas `v0.md` describes (`envelope.proto`,
  `sealed_sender.proto`, `prekey.proto`). Lint with:
  `protoc --proto_path=spec/proto --descriptor_set_out=/dev/null spec/proto/v0/*.proto`

Each future breaking revision gets its own `spec/vN.md` + `spec/proto/vN/`, published alongside
prior versions rather than overwriting them — see `v0.md` §3.
