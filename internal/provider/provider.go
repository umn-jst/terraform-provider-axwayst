package provider

import (
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure Provider satisfies various provider interfaces.
var _ provider.Provider = &axwaystProvider{}
var _ provider.ProviderWithFunctions = &axwaystProvider{}

// axwaystProvider defines the provider implementation.
type axwaystProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// axwaystProviderModel describes the provider data model.
type axwaystProviderModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`
	// Token    types.String `tfsdk:"token"`
}

func (p *axwaystProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "axwayst"
	resp.Version = p.version
}

func (p *axwaystProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provider for Axway Secure Transport",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Description: "URL for Axway ST Admin (i.e. https://axway.com:8443)",
				Optional:    true,
			},
			// "token": schema.StringAttribute{
			// 	Description: "Axway ST access token (instead of username/password)",
			// 	Optional:    true,
			// },
			"username": schema.StringAttribute{
				Description: "Axway ST username",
				Optional:    true,
			},
			"password": schema.StringAttribute{
				Description: "Axway ST password",
				Optional:    true,
			},
		},
	}
}

func (p *axwaystProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var (
		endpoint, username, password, auth string
	)

	var data axwaystProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if !data.Endpoint.IsNull() {
		endpoint = data.Endpoint.ValueString()
	} else {
		endpoint = os.Getenv("AXWAYST_HOST")
	}

	if endpoint == "" {
		resp.Diagnostics.AddError(
			"Missing API Endpoint Configuration",
			"While configuring the provider, the API endpoint hostname was not found in "+
				"the AXWAYST_HOST environment variable or provider "+
				"configuration block endpoint attribute.",
		)
		// Not returning early allows the logic to collect all errors.
	}

	if !data.Username.IsNull() {
		username = data.Username.ValueString()
	} else {
		username = os.Getenv("AXWAYST_USERNAME")
	}

	if !data.Password.IsNull() {
		password = data.Password.ValueString()
	} else {
		password = os.Getenv("AXWAYST_PASSWORD")
	}

	if username == "" {
		resp.Diagnostics.AddError(
			"Provider Configuration Error",
			"Specify a username (AXWAYST_USERNAME environment variable).")
		return
	}

	if password == "" {
		resp.Diagnostics.AddError(
			"Provider Configuration Error",
			"Specify a password (AXWAYST_PASSWORD environment variable).")
		return
	}

	authString := username + ":" + password
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(authString))
	auth = "Basic" + " " + encodedAuth

	httpclient := &http.Client{
		Timeout: 30 * time.Second,
	}

	client := new(AxwaySTClient)

	client.client = httpclient
	client.endpoint = endpoint
	client.auth = auth

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *axwaystProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewAdministratorsResource,
	}
}

func (p *axwaystProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		// NewAdministratorsDatasource,
	}
}

func (p *axwaystProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{
		//NewExampleFunction,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &axwaystProvider{
			version: version,
		}
	}
}
