#ifndef VERIFY_ROLE_POLICY_HPP
#define VERIFY_ROLE_POLICY_HPP

#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>

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

#endif // VERIFY_ROLE_POLICY_HPP
