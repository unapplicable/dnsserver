---
id: e66e49c7-f877-412b-ad3e-640e16da928b
created: '2026-04-06T21:06:45.388Z'
modified: '2026-04-06T21:06:45.388Z'
memory_type: conventions-pattern
tags: []
---
# Key Patterns and Conventions

## Code Quality Patterns
- **RAII**: MutexGuard for exception-safe mutex locking
- **Error Handling**: Rich DNSParseException with context (offset, packet length, error type)
- **Testing**: Catch2 for unit tests + shell integration scripts
- **Fuzzing**: Custom fuzzing tools for UDP queries and targeted attacks

## Security Practices
- Constant-time comparison (CRYPTO_memcmp) for MAC verification
- Stack protector and FORTIFY_SOURCE in release builds
- Position-independent execution (PIE)
- Bounds checking on all packet parsing

## Naming Conventions
- Classes: PascalCase (Message, Zone, RR, ACL)
- Methods: camelCase (unpack, pack, findRecordsByName)
- Files: Lowercase with underscores (dnsserver.cpp, zone_authority.cpp)
- Test files: test_*.cpp, test_*.sh

## Commit Message Convention
```
type(scope): description

[FIXES/CHANGES/PROTECTION/TESTING]: summary

- Bullet points for changes
```

Types: fix, refactor, build, add

## Configuration
- Makefile primary (CMakeLists.txt is stub)
- clang++ compiler
- C++14 standard
- OpenSSL + pthreads dependencies
