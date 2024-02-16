using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Azure.Identity;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Azure.Core;

namespace MyFunctionApp
{
    public static class ProcessIPBlocklistAndUpdateFrontDoorWaf
    {
        private static readonly HttpClient httpClient = new HttpClient();
        private static readonly string subscriptionId = Environment.GetEnvironmentVariable("AZURE_SUBSCRIPTION_ID") ?? throw new InvalidOperationException("Environment variable AZURE_SUBSCRIPTION_ID not set.");
        private static readonly string resourceGroupName = Environment.GetEnvironmentVariable("AZURE_RESOURCE_GROUP_NAME") ?? throw new InvalidOperationException("Environment variable AZURE_RESOURCE_GROUP_NAME not set.");
        private static readonly string policyName = Environment.GetEnvironmentVariable("WAF_POLICY_NAME") ?? throw new InvalidOperationException("Environment variable WAF_POLICY_NAME not set.");
        private static readonly Regex ipPattern = new Regex(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", RegexOptions.Compiled);

        [Function("ProcessIPBlocklistAndUpdateFrontDoorWaf")]
        public static async Task Run([TimerTrigger("0 */5 * * * *")] TimerInfo myTimer, FunctionContext context)
        {
            var logger = context.GetLogger("ProcessIPBlocklistAndUpdateFrontDoorWaf");
            var urls = new List<string>
            {
                "https://www.spamhaus.org/drop/edrop.txt",
                "https://check.torproject.org/exit-addresses",
                "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
            };

            try
            {
                var allIps = await FetchIPsFromUrlsAsync(urls, logger);
                if (allIps.Any())
                {
                    await UpdateFrontDoorWafPolicyAsync(allIps, logger);
                }
            }
            catch (Exception ex)
            {
                logger.LogError($"Error during IP processing: {ex.Message}");
            }
        }

        private static async Task<List<string>> FetchIPsFromUrlsAsync(IEnumerable<string> urls, ILogger logger)
        {
            var allIps = new List<string>();
            foreach (var url in urls)
            {
                try
                {
                    var response = await httpClient.GetStringAsync(url);
                    var ips = ParseIPs(response);
                    allIps.AddRange(ips);
                    logger.LogInformation($"Fetched and parsed {ips.Count} IPs from {url}");
                }
                catch (Exception ex)
                {
                    logger.LogError($"Error fetching or parsing data from {url}: {ex.Message}");
                }
            }
            return allIps;
        }

        private static List<string> ParseIPs(string data)
        {
            return ipPattern.Matches(data).Select(m => m.Value).Distinct().ToList();
        }

        private static async Task UpdateFrontDoorWafPolicyAsync(List<string> ips, ILogger logger)
        {
            var credential = new DefaultAzureCredential();
            var requestUri = $"https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/{policyName}?api-version=2022-05-01";

            var policyUpdate = new
            {
                tags = new Dictionary<string, string>(), // Assuming no tags are needed, otherwise fill this dictionary appropriately
                properties = new
                {
                    customRules = new
                    {
                        rules = new[]
                        {
                            new
                            {
                                name = "blocklist",
                                priority = 1,
                                action = "Block",
                                matchConditions = new[]
                                {
                                    new
                                    {
                                        matchVariable = "RemoteAddr",
                                        operatorProperty = "IPMatch",
                                        negationCondition = false,
                                        matchValues = ips.ToArray()
                                    }
                                }
                            }
                        }
                    }
                }
            };

            var jsonContent = JsonSerializer.Serialize(policyUpdate, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
            var content = new StringContent(jsonContent, System.Text.Encoding.UTF8, "application/json");

            // Acquire a token for the Azure Management scope
            var token = await credential.GetTokenAsync(new Azure.Core.TokenRequestContext(new[] { "https://management.azure.com/.default" }));

            try
            {
                using (var request = new HttpRequestMessage(HttpMethod.Patch, requestUri))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
                    request.Content = content;
                    var response = await httpClient.SendAsync(request);
                    if (!response.IsSuccessStatusCode)
                    {
                        var error = await response.Content.ReadAsStringAsync();
                        logger.LogError($"Failed to update Front Door WAF policy: {error}");
                    }
                    else
                    {
                        logger.LogInformation("Successfully updated Front Door WAF policy.");
                    }
                }
            }
            catch (HttpRequestException ex)
            {
                logger.LogError($"Error updating WAF Policy: {ex.Message}");
            }
        }
    }
}