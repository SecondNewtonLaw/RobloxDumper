//
// Created by Dottik on 12/10/2024.
//

#pragma once

#define ROBLOXDUMPER_ENABLE_DEBUG_LOGS true

// Begin Macro Definitions

#define assert_ex(condition, exception) { if (!(condition)) { throw exception; } }
#define assert(condition, message) { if (!(condition)) { throw std::exception { std::format("{} @ {}:{}", message, __FUNCTION__, std::string(__LINE__)).c_str() }; } }
