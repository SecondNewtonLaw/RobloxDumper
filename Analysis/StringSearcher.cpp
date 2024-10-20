//
// Created by Dottik on 19/10/2024.
//

#include <sstream>

#include "StringSearcher.hpp"

#include <Utilities.hpp>

#include "XrefSearcher.hpp"

std::shared_ptr<RobloxDumper::Analysis::StringSearcher> RobloxDumper::Analysis::StringSearcher::pInstance;

std::shared_ptr<RobloxDumper::Analysis::StringSearcher> RobloxDumper::Analysis::StringSearcher::GetSingleton() {
    if (nullptr == RobloxDumper::Analysis::StringSearcher::pInstance)
        RobloxDumper::Analysis::StringSearcher::pInstance = std::make_shared<RobloxDumper::Analysis::StringSearcher>();

    return RobloxDumper::Analysis::StringSearcher::pInstance;
}

std::optional<void *> RobloxDumper::Analysis::StringSearcher::GetStringAddressInTarget(
    const hat::process::module hModule,
    const std::string_view szTargetString) {
    std::stringstream stream{};

    auto str = szTargetString.data();
    while (*str != '\0') {
        stream << std::hex << static_cast<int>(*str);

        if (*(str + 1) != '\0')
            stream << " ";

        ++str;
    }

    const auto AOB = RobloxDumper::Utilities::ToUpper(stream.str());

    auto signature = hat::parse_signature(AOB).value();

    const auto pattern = hat::find_pattern(signature, ".rdata", hModule);

    return pattern.has_result() ? pattern.get() : nullptr;
}

std::vector<void *> RobloxDumper::Analysis::StringSearcher::FindStringXrefsInTarget(
    const hat::process::module hModule, const std::string_view szTargetString) {
    const auto remoteString = this->GetStringAddressInTarget(hModule, szTargetString);
    if (!remoteString.has_value()) return {};
    const auto xrefSearcher = XrefSearcher::GetSingleton();

    return xrefSearcher->GetXrefsForPointer(remoteString.value());
}
