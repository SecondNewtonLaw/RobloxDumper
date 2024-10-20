//
// Created by Dottik on 20/10/2024.
//

#pragma once
#include <map>
#include <string>

namespace RobloxDumper {
    class DumperState final {
        public:
        std::map<std::string, void *> FunctionMap;
        std::map<std::string, void *> FastFlagMap;
    };
} // RobloxDumper
