---
id: 5e0daa26-a589-463e-951e-7f9531e6eef1
created: '2026-04-06T21:02:25.946Z'
modified: '2026-04-06T21:02:25.946Z'
memory_type: conventions-pattern
tags: []
---
# DNS Server Build Configurations

## Build Modes (from Makefile)

### Debug
```
CXXFLAGS_DEBUG = -Wall -Wextra -std=c++14 -g -DLINUX
```
- No optimization, symbols included

### Release
```
CXXFLAGS_RELEASE = -Wall -Wextra -std=c++14 -O2 -march=native -DNDEBUG -DLINUX
```
- Optimized with native CPU instructions

### Release-LTO (Hardened)
```
CXXFLAGS_RELEASE_LTO = -Wall -Wextra -std=c++14 -O3 -flto -march=native -DNDEBUG -DLINUX \
                       -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
LDFLAGS_RELEASE_LTO = -flto -pie -Wl,-z,relro -Wl,-z,now
```
- Link-time optimization, security hardening enabled

## Build Commands
```bash
make                 # Debug build
make buildRelease    # Release build
make buildReleaseLTO # Hardened release build
```

## Security Hardening Features
- Stack protector (-fstack-protector-strong)
- Fortify source (_FORTIFY_SOURCE=2)
- Position-independent execution (fPIE, -pie)
- RELRO/NOW bind flags (-Wl,-z,relro -Wl,-z,now)

## Binary Size
- Debug: ~500KB+ (with debug symbols)
- Release: ~140KB (stripped)
