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

listener http:Listener ep0 = new (9090);

@http:ServiceConfig {treatNilableAsOptional: true}
service / on ep0 {

    # Automatically detect threats in an input string
    #
    # + payload - User-facing text input
    # + return - Result of automatic threat detection on the input string
    resource function post content/automatic/detect/'string(@http:Payload string payload) returns AutomaticThreatDetectionResult {
        return {
            containedSqlInjectionThreat: false,
            containedSsrfThreat: false,
            isXML: false,
            containedXxeThreat: false,
            containedJsonInsecureDeserializationAttack: false,
            containedXssThreat: true,
            isJSON: false,
            successful: true,
            cleanResult: false,
            originalInput: payload,
            isURL: false
        };
    }

    # Detect Insecure Deserialization JSON (JID) attacks in a string
    #
    # + payload - User-facing text input
    # + return - Result of the insecure deserialization JSON check
    resource function post content/insecure\-deserialization/'json/detect/'string(@http:Payload string payload) returns InsecureDeserializationResult {
        return {
            containedJsonInsecureDeserializationAttack: true,
            successful: true,
            originalInput: payload
        };
    }

    # Check text input for SQL Injection (SQLI) attacks
    #
    # + payload - User-facing text input
    # + return - Result of the SQL injection check
    resource function post content/sql\-injection/detect/'string(@http:Payload string payload) returns SqlInjectionResult {
        return {
            containedSqlInjectionAttack: true,
            successful: true,
            originalInput: payload
        };
    }

    # Protect text input from Cross-Site-Scripting (XSS) attacks through normalization
    #
    # + payload - User-facing text input
    # + return - Result of the XSS protection, including the normalized text
    resource function post content/xss/detect/'string(@http:Payload string payload) returns XssProtectionResult {
        return {
            normalizedResult: "alert(1)",
            containedXss: true,
            successful: true,
            originalInput: payload
        };
    }

    # Protect text input from XML External Entity (XXE) attacks
    #
    # + payload - User-facing text input
    # + return - Result of the XXE threat check
    resource function post content/xxe/detect/'xml/'string(@http:Payload string payload) returns XxeDetectionResult {
        return {
            successful: true,
            containedXxe: true
        };
    }

    # Check if IP address is a known threat
    #
    # + payload - IP address to check
    # + return - Result of the known-threat check on the IP address
    resource function post network/ip/is\-threat(@http:Payload string payload) returns IpThreatResponse {
        return {
            threatType: "Botnet",
            isThreat: true
        };
    }

    # Check if IP address is a bot
    #
    # + payload - IP address to check
    # + return - Result of the bot check on the IP address
    resource function post network/ip/is\-bot(@http:Payload string payload) returns BotCheckResponse {
        return {
            isBot: true
        };
    }

    # Check if IP address is a Tor exit node
    #
    # + payload - IP address to check
    # + return - Result of the Tor exit node check on the IP address
    resource function post network/ip/is\-tor\-node(@http:Payload string payload) returns TorNodeCheckResponse {
        return {
            isTorNode: false
        };
    }

    # Check a URL for Server-side Request Forgery (SSRF) threats
    #
    # + payload - Input URL request
    # + return - Result of the SSRF threat check on the URL
    resource function post network/url/ssrf/detect(@http:Payload SsrfDetectionRequest payload) returns SsrfDetectionResponse {
        return {
            threatLevel: "High",
            cleanURL: false
        };
    }
}
