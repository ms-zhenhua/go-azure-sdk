
## `github.com/hashicorp/go-azure-sdk/resource-manager/consumption/2019-10-01/forecasts` Documentation

The `forecasts` SDK allows for interaction with the Azure Resource Manager Service `consumption` (API Version `2019-10-01`).

This readme covers example usages, but further information on [using this SDK can be found in the project root](https://github.com/hashicorp/go-azure-sdk/tree/main/docs).

### Import Path

```go
import "github.com/hashicorp/go-azure-sdk/resource-manager/consumption/2019-10-01/forecasts"
```


### Client Initialization

```go
client := forecasts.NewForecastsClientWithBaseURI("https://management.azure.com")
client.Client.Authorizer = authorizer
```


### Example Usage: `ForecastsClient.List`

```go
ctx := context.TODO()
id := forecasts.NewSubscriptionID("12345678-1234-9876-4563-123456789012")

read, err := client.List(ctx, id, forecasts.DefaultListOperationOptions())
if err != nil {
	// handle the error
}
if model := read.Model; model != nil {
	// do something with the model/response object
}
```
