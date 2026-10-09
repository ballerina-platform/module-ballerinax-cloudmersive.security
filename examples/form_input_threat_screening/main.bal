// Screens a user-submitted form field for injection and scripting attacks before it is stored.

import ballerina/io;
import ballerinax/cloudmersive.security;

configurable string apiKey = ?;
configurable string userInput = ?;

public function main() returns error? {
    security:Client securityClient = check new ({apikey: apiKey});

    // The API expects the text as a JSON string, so encode it before sending.
    string payload = userInput.toJsonString();

    // Step 1: Run the automatic detector to see whether any known threat type is present.
    security:AutomaticThreatDetectionResult overall = check securityClient->detectThreats(payload);
    if overall.cleanResult is true {
        io:println("Input is clean, safe to store.");
        return;
    }
    io:println("Input flagged. SQL injection: ", overall.containedSqlInjectionThreat,
            ", XSS: ", overall.containedXssThreat);

    // Step 2: Confirm SQL injection specifically.
    security:SqlInjectionResult sqlResult = check securityClient->checkSqlInjection(payload);
    if sqlResult.containedSqlInjectionAttack is true {
        return error("Rejected: input contains a SQL injection attempt.");
    }

    // Step 3: Normalize any cross-site scripting content so the rest of the input can be kept.
    security:XssProtectionResult xssResult = check securityClient->protectXss(payload);
    string? normalized = xssResult.normalizedResult;
    if normalized is () {
        return error("XSS protection returned no normalized result.");
    }
    io:println("Sanitized input: ", normalized);
}
