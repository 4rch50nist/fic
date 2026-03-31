#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>
#include "ThreadSafeQueue.hpp"


template<typename T>
  void ThreadSafeQueue<T>::push(T &&item) {
    std::unique_lock lock(mx);

    cv_push.wait(lock, [&] { return q.size() < max_size || closed; });

    if (closed)
      return;

    q.push(std::move(item));
    lock.unlock();
    cv_pop.notify_one();
  }

template <typename T >
  std::optional<T> ThreadSafeQueue<T>::pop() {
    std::unique_lock lock(mx);
    cv_pop.wait(lock, [&] { return !q.empty() || closed; });

    if (q.empty())
      return std::nullopt;

    T item = std::move(q.front());
    q.pop();
    lock.unlock();
    cv_push.notify_one();
    return item;
  }

template <typename T>
  void ThreadSafeQueue<T>::close() {
    {
      std::lock_guard lock(mx);
      closed = true;
    }
    cv_pop.notify_all();
    cv_push.notify_all();
  }

template <typename T>
  bool ThreadSafeQueue<T>::is_closed() const noexcept
  {
    std::lock_guard lock(mx);
    return closed;
  }
