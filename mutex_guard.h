#ifndef HAVE_MUTEX_GUARD_H
#define HAVE_MUTEX_GUARD_H

#include <pthread.h>

template<typename Mutex>
class MutexGuard {
public:
	explicit MutexGuard(Mutex* mutex) : mutex_(mutex), locked_(false) {
		if (mutex_) {
			pthread_mutex_lock(mutex_);
			locked_ = true;
		}
	}
	
	~MutexGuard() {
		unlock();
	}
	
	void unlock() {
		if (mutex_ && locked_) {
			pthread_mutex_unlock(mutex_);
			locked_ = false;
		}
	}
	
	bool isLocked() const { return locked_; }
	
	// Prevent copy
	MutexGuard(const MutexGuard&) = delete;
	MutexGuard& operator=(const MutexGuard&) = delete;
	
	// Allow move
	MutexGuard(MutexGuard&& other) noexcept : mutex_(other.mutex_), locked_(other.locked_) {
		other.mutex_ = nullptr;
		other.locked_ = false;
	}
	
	MutexGuard& operator=(MutexGuard&& other) noexcept {
		if (this != &other) {
			unlock();
			mutex_ = other.mutex_;
			locked_ = other.locked_;
			other.mutex_ = nullptr;
			other.locked_ = false;
		}
		return *this;
	}

private:
	Mutex* mutex_;
	bool locked_;
};

#endif
