//
// Created by Dottik on 19/10/2024.
//

#pragma once
#include <vector>
#include <memory>
#include <optional>

#include <libhat/Process.hpp>

namespace RobloxDumper::Analysis {
    class StringSearcher {
        static std::shared_ptr<StringSearcher> pInstance;

    public:
        static std::shared_ptr<StringSearcher> GetSingleton();

        std::optional<void *> GetStringAddressInTarget(hat::process::module hModule, std::string_view szTargetString);

        std::vector<void *> FindStringXrefsInTarget(hat::process::module hModule, std::string_view szTargetString);
    };
};
