//
// pcap2json / ThreadPool.hh
// Created by brian on 2024-12-19.
//

#ifndef THREADPOOL_HH
#define THREADPOOL_HH
#include <atomic>
#include <functional>
#include <future>
#include <thread>
#include <vector>
#include <xlog/vendor/concurrent_queue.hh>

class ThreadPool {
public:
  explicit ThreadPool(size_t concurrency);
  ~ThreadPool();

  template <class F, class... Args>
  auto enqueue(F&& f, Args&&... args)
    -> std::future<std::result_of_t<F(Args...)>>;

private:
  std::vector<std::thread> workers_;
  using Task = std::function<void()>;
  moodycamel::ConcurrentQueue<Task> task_queue_;

  std::atomic<bool> stop_;
};

inline ThreadPool::ThreadPool(size_t const concurrency)
    : stop_{ false } {
  workers_.reserve(concurrency);
  using namespace std::chrono_literals;
  for (size_t i{ 0 }; i < concurrency; ++i) {
    workers_.emplace_back([this] {
      while (not stop_) {
        Task task;
        if (task_queue_.try_dequeue(task)) {
          task();
        } else {
          std::this_thread::sleep_for(20ms);
        }
      }
    });
  }
}

inline ThreadPool::~ThreadPool() {
  stop_ = true;
  for (std::thread& worker : workers_) worker.join();
}

template <class F, class... Args>
auto ThreadPool::enqueue(F&& f, Args&&... args)
  -> std::future<std::result_of_t<F(Args...)>> {
  using return_type = std::result_of_t<F(Args...)>;

  auto task{ std::make_shared<std::packaged_task<return_type()>>(
    std::bind(std::forward<F>(f), std::forward<Args>(args)...)) };

  std::future<return_type> res{ task->get_future() };
  if (stop_) throw std::runtime_error{ "enqueue on stopped ThreadPool" };
  task_queue_.enqueue([task] { (*task)(); });
  return res;
}

#endif // THREADPOOL_HH
