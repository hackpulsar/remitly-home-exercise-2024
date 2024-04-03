#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>

#include <iostream>

#include <catch2/catch_test_macros.hpp>

using json = nlohmann::json;

json read_role_policy_from_string(const std::string& sData)
{
    json jData = json::parse(sData);
    return jData;
}

json read_role_policy_from_file(const std::string& sFilepath)
{
    std::ifstream inputStream(sFilepath);
    if (inputStream.is_open())
    {
        std::stringstream ssRawData;
        ssRawData << inputStream.rdbuf();
        return read_role_policy_from_string(ssRawData.str());
    }
    else
        return json();
    inputStream.close();
}

bool verify_role_policy_resource(const json& jRolePolicy)
{
    if (!jRolePolicy.contains("PolicyName") && !jRolePolicy.contains("PolicyDocument"))
        throw "Input data format is not AWS::IAM::Role Policy.";

    if (jRolePolicy["PolicyDocument"]["Statement"][0]["Resource"] == "*") return false;
    else return true;
}

TEST_CASE("Verify input JSON data.", "[verify_role_policy_resource]")
{
    json j = read_role_policy_from_file("role_policy.json");

    REQUIRE(verify_role_policy_resource(j) == false);

    j["PolicyDocument"]["Statement"][0]["Resource"] = "***";
    REQUIRE(verify_role_policy_resource(j) == true);

    j["PolicyDocument"]["Statement"][0]["Resource"] = "";
    REQUIRE(verify_role_policy_resource(j) == true);

    j["PolicyDocument"]["Statement"][0]["Resource"] = "lvnvjuhrevpokwelkvjn";
    REQUIRE(verify_role_policy_resource(j) == true);

    j["PolicyDocument"]["Statement"][0]["Resource"] = { "random", "list" };
    REQUIRE(verify_role_policy_resource(j) == true);

    j["PolicyDocument"]["Statement"][0]["Resource"] = { { "random", "stuff" } };
    REQUIRE(verify_role_policy_resource(j) == true);

    j["PolicyDocument"]["Statement"][0]["Resource"] = { { "random", "stuff" }, { "some", "extra" } };
    REQUIRE(verify_role_policy_resource(j) == true);

}

