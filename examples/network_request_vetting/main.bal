// Vets an incoming client IP address and a user-supplied callback URL before accepting a webhook registration.

import ballerina/io;
import ballerinax/cloudmersive.security;

configurable string apiKey = ?;
configurable string clientIp = ?;
configurable string callbackUrl = ?;
configurable string[] blockedDomains = [];

public function main() returns error? {
    security:Client securityClient = check new ({apikey: apiKey});

    // The API expects the IP address as a JSON string, so encode it before sending.
    string ipPayload = clientIp.toJsonString();

    // Step 1: Check whether the IP address is a known threat.
    security:IpThreatResponse threat = check securityClient->checkIpThreat(ipPayload);
    if threat.isThreat is true {
        return error("Rejected: " + clientIp + " is a known threat (" + (threat.threatType ?: "unknown") + ").");
    }

    // Step 2: Check whether the IP address belongs to a bot.
    security:BotCheckResponse bot = check securityClient->checkIpBot(ipPayload);
    if bot.isBot is true {
        return error("Rejected: " + clientIp + " is a bot.");
    }

    // Step 3: Check whether the IP address is a Tor exit node.
    security:TorNodeCheckResponse tor = check securityClient->checkIpTorNode(ipPayload);
    if tor.isTorNode is true {
        return error("Rejected: " + clientIp + " is a Tor exit node.");
    }

    // Step 4: Make sure the callback URL cannot be used for server-side request forgery.
    security:SsrfDetectionResponse ssrf = check securityClient->detectSsrf({uRL: callbackUrl, blockedDomains});
    if ssrf.cleanURL is false {
        return error("Rejected: callback URL is a " + (ssrf.threatLevel ?: "unknown") + " SSRF risk.");
    }
    io:println("Client IP and callback URL passed all checks.");
}
