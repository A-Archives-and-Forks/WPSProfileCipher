#include "wps_profile_cipher/oem_signature.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

namespace
{

[[nodiscard]] std::vector<std::uint8_t> bytes(const std::string_view text)
{
    std::vector<std::uint8_t> result;
    result.reserve(text.size());
    for (const auto character : text)
    {
        result.push_back(static_cast<std::uint8_t>(character));
    }
    return result;
}

[[nodiscard]] std::string ascii(const std::span<const std::uint8_t> data)
{
    return { data.begin(), data.end() };
}

} // namespace

TEST_CASE("OEM signatures match a fixed-IV known answer", "[oem-signature]")
{
    const auto content = bytes("[setup]\r\nkey=value");
    wps::profile::OemSignature::InitializationVector initialization_vector {};
    for (std::size_t index = 0; index < initialization_vector.size(); ++index)
    {
        initialization_vector[index] = static_cast<std::uint8_t>(index);
    }

    const auto signed_content = wps::profile::OemSignature {}.append(content, initialization_vector);
    constexpr std::string_view expected =
        "[setup]\r\nkey=value\r\n"
        ";OemSignType1="
        "5332695334337035466C3A3F60496B57"
        "2202D521665B7736599689E9691AAEF62F01EC0A224E3A19FDB7CAB9DAF830955"
        "156E51F0967B6DF3961B7757F8B0EFB";
    REQUIRE(ascii(signed_content) == expected);
}
