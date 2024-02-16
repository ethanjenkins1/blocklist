using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using System.Linq;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Azure.Identity;
using Azure.Core;

public static class ProcessIPBlocklistAndUpdateFrontDoorWaf
{
    private static readonly HttpClient httpClient = new HttpClient();
    private static readonly string subscriptionId = Environment.GetEnvironmentVariable("AZURE_SUBSCRIPTION_ID") ?? throw new InvalidOperationException("Environment variable AZURE_SUBSCRIPTION_ID not set.");
    private static readonly string resourceGroupName = Environment.GetEnvironmentVariable("AZURE_RESOURCE_GROUP_NAME") ?? throw new InvalidOperationException("Environment variable AZURE_RESOURCE_GROUP_NAME not set.");
    private static readonly string policyName = Environment.GetEnvironmentVariable("WAF_POLICY_NAME") ?? throw new InvalidOperationException("Environment variable WAF_POLICY_NAME not set.");

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

        var allIps = await FetchIPsFromUrls(urls, logger);

        if (allIps.Any())
        {
            await UpdateFrontDoorWafPolicy(allIps, logger);
        }
    }

    private static async Task<List<string>> FetchIPsFromUrls(IEnumerable<string> urls, ILogger logger)
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
        var ipPattern = @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?\b";
        return Regex.Matches(data, ipPattern).Select(m => m.Value).Distinct().ToList();
    }

    private static async Task UpdateFrontDoorWafPolicy(List<string> ips, ILogger logger)
    {
        var tokenCredential = new DefaultAzureCredential();
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await GetAzureRestApiToken(tokenCredential));

        var requestUri = $"https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers//Microsoft.Network/frontdoorwebapplicationfirewallpolicies/{policyName}?api-version=2023-05-01";

        var policyUpdate = new
        {
            tags = new { Updated = DateTime.UtcNow.ToString("s") + "Z" },
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
                                    negationConditon = false,
                                    matchValues = ips.ToArray()
                                }
                            }
                        }
                    }
                }
            }
        };

        var jsonContent = JsonConvert.SerializeObject(policyUpdate);
        var content = new StringContent(jsonContent, System.Text.Encoding.UTF8, "application/json");

        var response = await httpClient.PatchAsync(requestUri, content);

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

    private static async Task<string> GetAzureRestApiToken(TokenCredential tokenCredential)
    {
        var requestContext = new TokenRequestContext(new[] { "https://management.azure.com/.default" });
        var accessToken = await tokenCredential.GetTokenAsync(requestContext, new CancellationToken());
        return accessToken.Token;
    }
}
