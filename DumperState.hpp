//
// Created by Dottik on 20/10/2024.
//

#pragma once
#include <map>
#include <string>
#include <vector>

namespace RobloxDumper {
    class DumperState final {
        public:
        std::map<std::string, std::vector<void*>> XrefMap;
        std::map<std::string, void *> FunctionMap;
        std::map<std::string, std::ptrdiff_t> OffsetMap;
        std::map<std::string, void *> FastFlagMap;
    };
} // RobloxDumper
