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

public static class ProcessIPBlocklistAndUpdateFrontDoorWaf
{
    private static readonly HttpClient httpClient = new HttpClient();
    private static readonly string subscriptionId = Environment.GetEnvironmentVariable("AZURE_SUBSCRIPTION_ID");
    private static readonly string resourceGroupName = Environment.GetEnvironmentVariable("AZURE_RESOURCE_GROUP_NAME");
    private static readonly string policyName = Environment.GetEnvironmentVariable("WAF_POLICY_NAME"); // Assuming WAF_POLICY_NAME is the policy name

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

        if (allIps.Any())
        {
            await UpdateFrontDoorWafPolicy(allIps, logger);
        }
    }

    private static List<string> ParseIPs(string data)
    {
        var ipPattern = @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?\b";
        return Regex.Matches(data, ipPattern).Select(m => m.Value).Distinct().ToList();
    }

    private static async Task UpdateFrontDoorWafPolicy(List<string> ips, ILogger logger)
    {
        var token = await GetAzureRestApiToken();
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var requestUri = $"https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cdn/cdnWebApplicationFirewallPolicies/{policyName}?api-version=2023-05-01";

        var policyUpdate = new
        {
            tags = new { Updated = DateTime.UtcNow.ToString("s") + "Z" }, // Example of updating tags, adapt as necessary
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

    private static async Task<string> GetAzureRestApiToken()
    {
        var credential = new DefaultAzureCredential();
        var tokenRequestContext = new TokenRequestContext(new[] { "https://management.azure.com/.default" });
        var accessToken = await credential.GetTokenAsync(tokenRequestContext);
        return accessToken.Token;
    }

}