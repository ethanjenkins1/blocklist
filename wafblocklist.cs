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
    private static readonly string subscriptionId = Environment.GetEnvironmentVariable("AZURE_SUBSCRIPTION_ID") ?? throw new InvalidOperationException("Environment variable AZURE_SUBSCRIPTION_ID not set.");
    private static readonly string resourceGroupName = Environment.GetEnvironmentVariable("AZURE_RESOURCE_GROUP_NAME") ?? throw new InvalidOperationException("Environment variable AZURE_RESOURCE_GROUP_NAME not set.");
    private static readonly string policyName = Environment.GetEnvironmentVariable("WAF_POLICY_NAME") ?? throw new InvalidOperationException("Environment variable WAF_POLICY_NAME not set.");

    [Function("ProcessIPBlocklistAndUpdateFrontDoorWaf")]
    public static async Task Run([TimerTrigger("0 */5 * * * *")] TimerInfo myTimer, FunctionContext context)
    {
        var logger = context.GetLogger("ProcessIPBlocklistAndUpdateFrontDoorWaf");
        logger.LogInformation($"Function triggered at: {DateTime.Now}");

        // Directly using a specified IP address for the example
        await UpdateFrontDoorWafPolicy(logger);
    }

    private static async Task UpdateFrontDoorWafPolicy(ILogger logger)
    {
        var tokenCredential = new DefaultAzureCredential();
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await GetAzureRestApiToken(tokenCredential));

        string[] specifiedIP = { "104.129.55.106" }; // Manually set IP

        var requestUri = $"https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/{policyName}?api-version=2022-05-01";

        var policyUpdate = new
        {
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
                                    matchValues = specifiedIP
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
            logger.LogInformation("Successfully updated Front Door WAF policy with the specified IP.");
        }
    }

    private static async Task<string> GetAzureRestApiToken(TokenCredential tokenCredential)
    {
        var requestContext = new TokenRequestContext(new[] { "https://management.azure.com/.default" });
        var accessToken = await tokenCredential.GetTokenAsync(requestContext);
        return accessToken.Token;
    }
}
