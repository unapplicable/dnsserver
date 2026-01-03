# TCP Denial-of-Service Mitigation Strategies

## Current Vulnerability

The DNS server is vulnerable to slowloris-style TCP attacks where an attacker:
1. Opens TCP connections but never sends data (or sends very slowly)
2. Blocks the main server thread indefinitely with synchronous `recv()` calls
3. Can completely disable the server with just 2-3 slow connections

## Alternative Design Proposals

### Option 1: Socket-Level Receive Timeout (RECOMMENDED)
**Approach:** Set `SO_RCVTIMEO` on accepted TCP sockets

**Pros:**
- Simplest implementation (10-15 lines of code)
- No architectural changes needed
- Works on both Linux and Windows
- Minimal performance impact
- Most appropriate for DNS (expects fast request/response)

**Cons:**
- Fixed timeout for all connections
- Still processes connections serially

**Implementation:**
```cpp
// After accept(), set receive timeout
struct timeval timeout;
timeout.tv_sec = 5;  // 5 second timeout
timeout.tv_usec = 0;
setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
```

**Recommended timeout:** 5-10 seconds (DNS over TCP should be fast)

---

### Option 2: Non-blocking Sockets with select()/poll()
**Approach:** Use non-blocking mode with `select()` before each `recv()`

**Pros:**
- Fine-grained control over timeouts
- Can handle partial reads
- More flexible than socket-level timeout

**Cons:**
- More complex code (~40-50 lines)
- Still single-threaded (one slow connection blocks others)
- More system calls (select + recv)

**Implementation:**
```cpp
fd_set readfds;
FD_ZERO(&readfds);
FD_SET(client, &readfds);
struct timeval tv = {5, 0};
if (select(client + 1, &readfds, NULL, NULL, &tv) <= 0) {
    // Timeout or error
    closesocket_compat(client);
    continue;
}
// Now recv() won't block
```

---

### Option 3: Thread Pool for TCP Connections
**Approach:** Spawn worker threads to handle TCP connections

**Pros:**
- True concurrency - multiple TCP connections processed simultaneously
- Main thread stays responsive
- Can set per-thread timeouts

**Cons:**
- Significant architectural change (~200+ lines)
- Need thread synchronization for zone access (already have mutex)
- Resource overhead (threads, memory)
- Thread pool management complexity
- Need max connection limit to prevent thread exhaustion

**Implementation Overview:**
- Create fixed-size thread pool on startup (e.g., 10 threads)
- Main thread accepts connections, queues to worker threads
- Workers handle full TCP request/response lifecycle
- Need connection queue with max size

---

### Option 4: Fork/Process Per Connection
**Approach:** Fork child process for each TCP connection (Unix only)

**Pros:**
- Complete isolation between connections
- Simple code (fork + handle + exit)

**Cons:**
- High overhead (process creation)
- Not portable (Linux only)
- Need IPC or shared memory for zone data
- Inappropriate for DNS (too heavy)
- **NOT RECOMMENDED** for this use case

---

### Option 5: Event-Driven Architecture (epoll/kqueue)
**Approach:** Use epoll (Linux) or kqueue (BSD) for event-driven I/O

**Pros:**
- Scales to many concurrent connections
- Efficient for high-connection scenarios
- Non-blocking by design

**Cons:**
- Major rewrite (500+ lines)
- Platform-specific code
- Complex state machine for partial reads
- Overkill for typical DNS server load
- **NOT RECOMMENDED** unless expecting 1000+ concurrent TCP connections

---

## Recommendation

**Implement Option 1: Socket-Level Receive Timeout**

### Rationale:
1. **Minimal code change** - Only ~10 lines added
2. **Effective protection** - Prevents indefinite blocking
3. **DNS-appropriate** - DNS over TCP is meant to be fast; legitimate clients will complete within seconds
4. **Cross-platform** - Works on Linux and Windows
5. **No architectural risk** - Preserves existing single-threaded design
6. **Easy to test** - Simple to verify with timeout tests

### Recommended Configuration:
- **Timeout:** 10 seconds (generous for DNS)
- **Location:** Immediately after `accept()` on line 774
- **Behavior:** Log timeout events, close socket, continue serving other requests

### Future Enhancements (if needed):
- If concurrent TCP load increases, add Option 3 (Thread Pool)
- Monitor server logs for timeout frequency
- Consider separate timeout for length-prefix (2 bytes) vs full message

### Implementation Priority:
1. ✅ Add socket receive timeout (Option 1)
2. 📋 Add timeout logging and metrics
3. 📋 Add max concurrent TCP connection limit (defense in depth)
4. 📋 Consider thread pool if TCP load warrants it (Option 3)
