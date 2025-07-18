#pragma once
#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

class PubSubManager {
public:
  PubSubManager();

private:
  std::unordered_map<std::string, std::vector<size_t>> listeners;
};
