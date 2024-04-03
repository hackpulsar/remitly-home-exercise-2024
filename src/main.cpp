#include <catch2/catch_test_macros.hpp>
#include "verify_role_policy.hpp"

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

