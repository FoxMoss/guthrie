#pragma once
#include <cstddef>
#include <functional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

template <typename Packet> class PubSubManager {
public:
  PubSubManager(std::function<bool(size_t id, Packet packet)> callback)
      : callback(callback) {}

  void listen(std::string channel, size_t self_id) {
    if (!listeners.contains(channel))
      listeners[channel] = {};
    listeners[channel].insert(self_id);
  }
  void remove_listener(std::string channel, size_t self_id) {
    if (!listeners.contains(channel))
      return;
    if (listeners[channel].contains(self_id))
      listeners[channel].erase(self_id);
    if (listeners[channel].size() == 0)
      listeners.erase(channel);
  }
  void send(std::string channel, Packet packet) {
    if (!listeners.contains(channel))
      return;
    std::vector<size_t> id_expired;
    for (auto id : listeners[channel])
      if (!callback(id, packet))
        id_expired.push_back(id);

    // this bit is a fail safe! it should never be triggered but there might be
    // a race condition that will trigger it. if someone could go wrong in a
    // proccess meant to run for hundreds if not thousands of hours it will, we
    // can only mitigate
    for (auto id : id_expired)
      remove_listener(channel, id);
  }

private:
  std::unordered_map<std::string, std::set<size_t>> listeners;
  std::function<bool(size_t id, Packet packet)> callback;
};
