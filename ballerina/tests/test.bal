// Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/http;
import ballerina/os;
import ballerina/test;

final boolean isLiveServer = os:getEnv("IS_LIVE_SERVER") == "true";
final string serviceUrl = isLiveServer ? "https://api.cloudmersive.com/security/threat-detection" : "http://localhost:9090";
final string apiKey = isLiveServer ? os:getEnv("CLOUDMERSIVE_API_KEY") : "test_api_key";

final Client securityClient = check new ({apikey: apiKey}, {httpVersion: http:HTTP_1_1}, serviceUrl);

@test:Config {groups: ["live_tests", "mock_tests"]}
isolated function testDetectThreats() returns error? {
    AutomaticThreatDetectionResult response = check securityClient->detectThreats("<script>alert(1)</script>".toJsonString());
    test:assertTrue(response?.successful is boolean);
    test:assertTrue(response?.cleanResult is boolean);
}

@test:Config {groups: ["live_tests", "mock_tests"]}
isolated function testDetectInsecureDeserialization() returns error? {
    InsecureDeserializationResult response = check securityClient->detectInsecureDeserialization("{\"$type\":\"System.Diagnostics.Process\"}".toJsonString());
    test:assertTrue(response?.successful is boolean);
}

@test:Config {groups: ["live_tests", "mock_tests"]}
isolated function testCheckSqlInjection() returns error? {
    SqlInjectionResult response = check securityClient->checkSqlInjection("' OR 1=1 --".toJsonString());
    test:assertTrue(response?.containedSqlInjectionAttack is boolean);
}

@test:Config {groups: ["live_tests", "mock_tests"]}
isolated function testProtectXss() returns error? {
    XssProtectionResult response = check securityClient->protectXss("<script>alert(1)</script>".toJsonString());
    test:assertTrue(response?.containedXss is boolean);
}

@test:Config {groups: ["live_tests", "mock_tests"]}
isolated function testCheckXxe() returns error? {
    XxeDetectionResult response = check securityClient->checkXxe("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>".toJsonString());
    test:assertTrue(response?.containedXxe is boolean);
}

@test:Config {groups: ["live_tests", "mock_tests"]}
isolated function testDetectSsrf() returns error? {
    SsrfDetectionRequest request = {uRL: "http://169.254.169.254/latest/meta-data", blockedDomains: ["internal.example.com"]};
    SsrfDetectionResponse response = check securityClient->detectSsrf(request);
    test:assertTrue(response?.cleanURL is boolean);
}

@test:Config {groups: ["live_tests", "mock_tests"]}
isolated function testCheckIpThreat() returns error? {
    IpThreatResponse response = check securityClient->checkIpThreat("55.55.55.55".toJsonString());
    test:assertTrue(response?.isThreat is boolean);
}

@test:Config {groups: ["live_tests", "mock_tests"]}
isolated function testCheckIpBot() returns error? {
    BotCheckResponse response = check securityClient->checkIpBot("55.55.55.55".toJsonString());
    test:assertTrue(response?.isBot is boolean);
}

@test:Config {groups: ["live_tests", "mock_tests"]}
isolated function testCheckIpTorNode() returns error? {
    TorNodeCheckResponse response = check securityClient->checkIpTorNode("55.55.55.55".toJsonString());
    test:assertTrue(response?.isTorNode is boolean);
}
