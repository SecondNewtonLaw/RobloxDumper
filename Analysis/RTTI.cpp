//
// Created by Dottik on 12/10/2024.
//

#include <RTTIHook/RTTIScanner.h>
#include "RTTI.hpp"

#include <Logger.hpp>
#include <mutex>
#include <optional>

std::shared_ptr<RobloxDumper::Analysis::RTTI> RobloxDumper::Analysis::RTTI::pInstance;

std::mutex RbxStuAnalysisRTTIGetSingleton;

bool RobloxDumper::Analysis::RTTI::IsInitialized() {
    return this->m_bIsInitialized;
}

void RobloxDumper::Analysis::RTTI::Initialize() {
    if (this->IsInitialized()) return;

    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::Analysis_RTTI, "-- Scanning for RTTI...");
    this->pRTTIScanner = std::make_shared<RTTIScanner>();

    this->pRTTIScanner->scan();
    this->pRTTIScanner->scan();
    this->pRTTIScanner->scan();
    this->pRTTIScanner->scan();
    this->pRTTIScanner->scan();

    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::Analysis_RTTI,
              std::format("-- RTTI scan completed, found {} RTTI objects in PE.", RTTIScanner::classRTTI.size()));

    RobloxDumperLog(RobloxDumper::LogType::Information, RobloxDumper::Analysis_RTTI,
              "-- Results saved to memory.");


    this->m_bIsInitialized = true;
}

std::optional<std::shared_ptr<RTTIScanner::RTTI> > RobloxDumper::Analysis::RTTI::GetRuntimeTypeInformation(
    const std::string_view name) {
    if (!this->IsInitialized()) return {}; // Invalid access.

    if (!RTTIScanner::classRTTI.contains(name))
        return {};

    auto info = RTTIScanner::classRTTI.at(name);
    return info;
}

std::shared_ptr<RobloxDumper::Analysis::RTTI> RobloxDumper::Analysis::RTTI::GetSingleton() {
    if (RobloxDumper::Analysis::RTTI::pInstance == nullptr)
        RobloxDumper::Analysis::RTTI::pInstance = std::make_shared<RobloxDumper::Analysis::RTTI>();

    if (!RobloxDumper::Analysis::RTTI::pInstance->IsInitialized()) {
        std::scoped_lock lock{RbxStuAnalysisRTTIGetSingleton};
        if (RobloxDumper::Analysis::RTTI::pInstance->IsInitialized())
            return RobloxDumper::Analysis::RTTI::pInstance;

        RobloxDumper::Analysis::RTTI::pInstance->Initialize();
    }
    return RobloxDumper::Analysis::RTTI::pInstance;
}
