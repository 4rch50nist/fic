#pragma once
#include <condition_variable>
#include <queue>
#include <mutex>
#include <optional>

template <typename T> class ThreadSafeQueue
{
    std::queue<T> q;
    mutable std::mutex mx;
    std::condition_variable cv_pop;
    std::condition_variable cv_push;

    const size_t max_size;
    bool closed = false;

public:

    explicit ThreadSafeQueue(size_t max_size = 16) : max_size{max_size} {}


    void push(T &&);
    void close();
    std::optional<T>  pop();
    [[nodiscard]] bool is_closed () const noexcept ;
    
};