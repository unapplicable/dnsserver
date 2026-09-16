---
id: 75654e87-e191-405f-8783-60f3f01f45ce
created: '2026-04-06T21:15:34.000Z'
modified: '2026-04-06T21:15:34.000Z'
memory_type: project-preference
tags:
  - build
  - makefile
---
Build using Makefile with clang++ (C++14).

Targets:
- `make` or `make all` - debug build (default)
- `make release` - optimized release
- `make release-lto` - LTO + security hardened
- `make test` - run unit tests
- `make test-integration` - run integration tests
- `make test-all` - run all tests
- `make clean` - clean build artifacts
- `make run-test` - run server on test zone (port 5353)

Dependencies: pthread, ssl, crypto
