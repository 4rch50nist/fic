#pragma once

#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>

template <typename T> class ThreadSafeQueue {
  std::queue<T> q;
  std::mutex mx;
  std::condition_variable cv;

  const size_t max_size = 16;
  bool closed = false;

public:
  explicit ThreadSafeQueue(size_t max_size = 16) : max_size{max_size} {}

  void push(T item) {
    std::unique_lock lock(mx);

    cv.wait(lock, [&] { return q.size() < max_size || closed; });

    if (closed)
      return;

    q.push(std::move(item));
    lock.unlock();
    cv.notify_one();
  }

  std::optional<T> pop() {
    std::unique_lock lock(mx);
    cv.wait(lock, [&] { return !q.empty || closed; });

    if (q.empty())
      return std::nullopt;

    T item = std::move(q.front());
    q.pop();
    lock.unlock();
    cv.notify_one();
    return item;
  }

  void close() {
    {
      std::lock_guard lock(mx);
      closed = true;
    }
    cv.notify_all();
  }

  bool is_closed() const {
    std::lock_guard lock(mx);
    return closed;
  }
};
