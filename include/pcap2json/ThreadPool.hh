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

  void JoinAll();
  void WorkFunc();

private:
  using Task = std::function<void()>;
  std::vector<std::thread> worker_threads_;
  moodycamel::ConcurrentQueue<Task> task_queue_;

  std::atomic<bool> stop_;
};

inline ThreadPool::ThreadPool(size_t const concurrency)
    : stop_{ false } {
  worker_threads_.reserve(concurrency);
  for (size_t i{ 0 }; i < concurrency; ++i) {
    worker_threads_.emplace_back([this] { WorkFunc(); });
  }
}

inline void ThreadPool::JoinAll() {
  stop_ = true;
  for (std::thread& worker : worker_threads_) worker.join();
  assert(task_queue_.size_approx() == 0);
  XLOG_DEBUG << "queue size: " << task_queue_.size_approx();
}

inline void ThreadPool::WorkFunc() {
  using namespace std::chrono_literals;
  int round{ 0 }, miss{ 0 };
  while (not stop_ or task_queue_.size_approx()) {
    Task task;
    if (task_queue_.try_dequeue(task)) {
      task();
      round = 0;
      miss = 0;
    } else {
      round = std::min(7, round);
      auto const curr{ 2ms * (1 << round) };
      std::this_thread::sleep_for(curr);
      round++;
      miss++;
      if (miss == 10) {
        XLOG_WARN << "连续 508ms 读不到新的任务，线程退出.";
        break;
      }
    }
  }
}

inline ThreadPool::~ThreadPool() {
  if (stop_) return;
  JoinAll();
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
