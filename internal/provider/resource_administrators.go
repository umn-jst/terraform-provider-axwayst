package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &AdministratorsResource{}

var _ resource.ResourceWithImportState = &AdministratorsResource{}

func NewAdministratorsResource() resource.Resource {
	return &AdministratorsResource{}
}

type AdministratorsResource struct {
	client *AxwaySTClient
}

func (r *AdministratorsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_administrators"
}

func (r *AdministratorsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: `Manage AxwayST administrators.`,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:    true,
				Description: "Administrator username i.e. `login_name`",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`),
						"login_name can only contain letters, numbers, dashes, and underscores",
					),
				},
			},
			"role_name": schema.StringAttribute{
				Required:    true,
				Description: "Must match an existing administrative role. Predefined administrative roles are: `Master Administrator`, `Database Administrator`, `Setup Administrator`, `Account Manager`, `Application Manager`, `Delegated Administrator`",
			},
			"is_limited": schema.BoolAttribute{
				Optional: true,
				Default:  booldefault.StaticBool(false),
				Computed: true,
			},
			"local_authentication": schema.BoolAttribute{
				Optional: true,
				Default:  booldefault.StaticBool(true),
				Computed: true,
			},
			"certificate_dn": schema.StringAttribute{
				Optional: true,
			},
			"dual_authentication": schema.BoolAttribute{
				Optional: true,
				Default:  booldefault.StaticBool(false),
				Computed: true,
			},
			"locked": schema.BoolAttribute{
				Optional: true,
				Default:  booldefault.StaticBool(false),
				Computed: true,
			},
			"parent": schema.StringAttribute{
				Optional: true,
			},
			"full_creation_path": schema.StringAttribute{
				Optional:    true,
				Description: "Applies only to delegated administrators. Shows the path for the parent administrator. For example, the path might look like: `admin/deladmin1/subdeladmin1`",
			},
			"password_credentials": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"password": schema.StringAttribute{
						Optional: true,
						Computed: true,
						Default:  stringdefault.StaticString(""),
					},
					"password_expired": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(false),
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"password":         types.StringType,
							"password_expired": types.BoolType,
						},
						map[string]attr.Value{
							"password":         types.StringValue(""),
							"password_expired": types.BoolValue(false),
						},
					),
				),
			},
			"administrator_rights": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"can_read_only": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(false),
					},
					"is_maker": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"is_checker": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"can_create_users": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"can_update_users": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"can_access_help_desk": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"can_see_full_audit_log": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"can_manage_administrators": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"can_manage_applications": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"can_manage_shared_folders": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"can_manage_business_units": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"can_manage_route_templates": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"can_manage_external_script_step": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"can_manage_external_script_root_execution": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"can_manage_login_restriction_policies": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"can_manage_icap_settings": schema.BoolAttribute{
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"can_read_only":                             types.BoolType,
							"is_maker":                                  types.BoolType,
							"is_checker":                                types.BoolType,
							"can_create_users":                          types.BoolType,
							"can_update_users":                          types.BoolType,
							"can_access_help_desk":                      types.BoolType,
							"can_see_full_audit_log":                    types.BoolType,
							"can_manage_administrators":                 types.BoolType,
							"can_manage_applications":                   types.BoolType,
							"can_manage_shared_folders":                 types.BoolType,
							"can_manage_business_units":                 types.BoolType,
							"can_manage_route_templates":                types.BoolType,
							"can_manage_external_script_step":           types.BoolType,
							"can_manage_external_script_root_execution": types.BoolType,
							"can_manage_login_restriction_policies":     types.BoolType,
							"can_manage_icap_settings":                  types.BoolType,
						},
						map[string]attr.Value{
							"can_read_only":                             types.BoolValue(false),
							"is_maker":                                  types.BoolValue(true),
							"is_checker":                                types.BoolValue(true),
							"can_create_users":                          types.BoolValue(true),
							"can_update_users":                          types.BoolValue(true),
							"can_access_help_desk":                      types.BoolValue(true),
							"can_see_full_audit_log":                    types.BoolValue(true),
							"can_manage_administrators":                 types.BoolValue(true),
							"can_manage_applications":                   types.BoolValue(true),
							"can_manage_shared_folders":                 types.BoolValue(true),
							"can_manage_business_units":                 types.BoolValue(true),
							"can_manage_route_templates":                types.BoolValue(true),
							"can_manage_external_script_step":           types.BoolValue(true),
							"can_manage_external_script_root_execution": types.BoolValue(true),
							"can_manage_login_restriction_policies":     types.BoolValue(true),
							"can_manage_icap_settings":                  types.BoolValue(true),
						},
					),
				),
			},
			"business_units": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Default: setdefault.StaticValue(
					types.SetValueMust(
						types.StringType,
						[]attr.Value{},
					),
				),
				Computed: true,
			},
		},
	}
}

func (r *AdministratorsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	configureData, ok := req.ProviderData.(*AxwaySTClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *http.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = configureData
}

func (r *AdministratorsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AdministratorsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var bodyData AdministratorsAPIModel

	bodyData.LoginName = data.LoginName.ValueString()
	bodyData.RoleName = data.RoleName.ValueString()
	bodyData.IsLimited = data.IsLimited.ValueBool()
	bodyData.LocalAuthentication = data.LocalAuthentication.ValueBool()
	bodyData.DualAuthentication = data.DualAuthentication.ValueBool()
	bodyData.Locked = data.Locked.ValueBool()

	bodyData.PasswordCredentials.Password = data.PasswordCredentials.Attributes()["password"].(types.String).ValueString()
	bodyData.PasswordCredentials.PasswordExpired = data.PasswordCredentials.Attributes()["password_expired"].(types.Bool).ValueBool()

	bodyData.AdministratorRights.CanReadOnly = data.AdministratorRights.Attributes()["can_read_only"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.IsMaker = data.AdministratorRights.Attributes()["is_maker"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.IsChecker = data.AdministratorRights.Attributes()["is_checker"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanCreateUsers = data.AdministratorRights.Attributes()["can_create_users"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanUpdateUsers = data.AdministratorRights.Attributes()["can_update_users"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanAccessHelpDesk = data.AdministratorRights.Attributes()["can_access_help_desk"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanSeeFullAuditLog = data.AdministratorRights.Attributes()["can_see_full_audit_log"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageAdministrators = data.AdministratorRights.Attributes()["can_manage_administrators"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageApplications = data.AdministratorRights.Attributes()["can_manage_applications"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageSharedFolders = data.AdministratorRights.Attributes()["can_manage_shared_folders"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageBusinessUnits = data.AdministratorRights.Attributes()["can_manage_business_units"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageRouteTemplates = data.AdministratorRights.Attributes()["can_manage_route_templates"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageExternalScriptStep = data.AdministratorRights.Attributes()["can_manage_external_script_step"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageExternalScriptRootExecution = data.AdministratorRights.Attributes()["can_manage_external_script_root_execution"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageLoginRestrictionPolicies = data.AdministratorRights.Attributes()["can_manage_login_restriction_policies"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageIcapSettings = data.AdministratorRights.Attributes()["can_manage_icap_settings"].(types.Bool).ValueBool()

	if len(data.BusinessUnits.Elements()) == 0 {
		bodyData.BusinessUnits = []string{}
	} else {
		for _, element := range data.BusinessUnits.Elements() {
			if str, ok := element.(types.String); ok {
				bodyData.BusinessUnits = append(bodyData.BusinessUnits, str.ValueString())
			} else {
				resp.Diagnostics.AddError(
					"Error converting BusinessUnit elements to string",
					fmt.Sprintf("Business units set: %v.", data.BusinessUnits))
				return
			}
		}
	}

	if !(data.CertificateDn.IsNull()) {
		bodyData.CertificateDn = data.CertificateDn.ValueString()
	}
	if !(data.Parent.IsNull()) {
		bodyData.Parent = data.Parent.ValueString()
	}
	if !(data.FullCreationPath.IsNull()) {
		bodyData.FullCreationPath = data.FullCreationPath.ValueString()
	}

	url := "/api/v2.0/administrators/"
	_, err := r.client.CreateUpdateAPIRequest(ctx, http.MethodPost, url, bodyData, []int{201})
	if err != nil {
		resp.Diagnostics.AddError(
			"Error making API http request",
			fmt.Sprintf("Error was: %s.", err.Error()))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AdministratorsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data AdministratorsModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	loginName := strings.Trim(data.LoginName.String(), "\"")
	url := fmt.Sprintf("/api/v2.0/administrators/%s/", loginName)

	body, statusCode, err := r.client.GenericAPIRequest(ctx, http.MethodGet, url, nil, []int{200, 404})
	if err != nil {
		resp.Diagnostics.AddError(
			"Error making API http request",
			fmt.Sprintf("Error was: %s.", err.Error()))
		return
	}

	if statusCode == 404 {
		resp.State.RemoveResource(ctx)
		return
	}

	var responseData AdministratorsAPIModel

	err = json.Unmarshal(body, &responseData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to unmarshal json",
			fmt.Sprintf("bodyData: %+v.", body))
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), responseData.LoginName)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role_name"), responseData.RoleName)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("is_limited"), responseData.IsLimited)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("local_authentication"), responseData.LocalAuthentication)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("dual_authentication"), responseData.DualAuthentication)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("locked"), responseData.Locked)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("business_units"), responseData.BusinessUnits)...)

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("password_credentials").AtName("password_expired"), responseData.PasswordCredentials.PasswordExpired)...)

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_read_only"), responseData.AdministratorRights.CanReadOnly)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("is_maker"), responseData.AdministratorRights.IsMaker)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("is_checker"), responseData.AdministratorRights.IsChecker)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_create_users"), responseData.AdministratorRights.CanCreateUsers)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_update_users"), responseData.AdministratorRights.CanUpdateUsers)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_access_help_desk"), responseData.AdministratorRights.CanAccessHelpDesk)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_see_full_audit_log"), responseData.AdministratorRights.CanSeeFullAuditLog)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_administrators"), responseData.AdministratorRights.CanManageAdministrators)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_applications"), responseData.AdministratorRights.CanManageApplications)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_shared_folders"), responseData.AdministratorRights.CanManageSharedFolders)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_business_units"), responseData.AdministratorRights.CanManageBusinessUnits)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_route_templates"), responseData.AdministratorRights.CanManageRouteTemplates)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_external_script_step"), responseData.AdministratorRights.CanManageExternalScriptStep)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_external_script_root_execution"), responseData.AdministratorRights.CanManageExternalScriptRootExecution)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_login_restriction_policies"), responseData.AdministratorRights.CanManageLoginRestrictionPolicies)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_icap_settings"), responseData.AdministratorRights.CanManageIcapSettings)...)

	if !(data.CertificateDn.IsNull() && responseData.CertificateDn == "") {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("certificate_dn"), responseData.CertificateDn)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	if !(data.Parent.IsNull() && responseData.Parent == "") {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("parent"), responseData.Parent)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	if !(data.FullCreationPath.IsNull() && responseData.FullCreationPath == "") {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("full_creation_path"), responseData.FullCreationPath)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Always use current state of password to set resp.State as responseData.Password will not be valid
	var statePassword types.String
	diags := req.State.GetAttribute(ctx, path.Root("password_credentials").AtName("password"), &statePassword)
	if diags.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("password_credentials").AtName("password"), statePassword)...)
}

func (r *AdministratorsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data AdministratorsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var bodyData AdministratorsAPIModel

	bodyData.LoginName = data.LoginName.ValueString()
	bodyData.RoleName = data.RoleName.ValueString()
	bodyData.IsLimited = data.IsLimited.ValueBool()
	bodyData.LocalAuthentication = data.LocalAuthentication.ValueBool()
	bodyData.DualAuthentication = data.DualAuthentication.ValueBool()
	bodyData.Locked = data.Locked.ValueBool()

	bodyData.PasswordCredentials.Password = data.PasswordCredentials.Attributes()["password"].(types.String).ValueString()
	bodyData.PasswordCredentials.PasswordExpired = data.PasswordCredentials.Attributes()["password_expired"].(types.Bool).ValueBool()

	bodyData.AdministratorRights.CanReadOnly = data.AdministratorRights.Attributes()["can_read_only"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.IsMaker = data.AdministratorRights.Attributes()["is_maker"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.IsChecker = data.AdministratorRights.Attributes()["is_checker"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanCreateUsers = data.AdministratorRights.Attributes()["can_create_users"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanUpdateUsers = data.AdministratorRights.Attributes()["can_update_users"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanAccessHelpDesk = data.AdministratorRights.Attributes()["can_access_help_desk"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanSeeFullAuditLog = data.AdministratorRights.Attributes()["can_see_full_audit_log"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageAdministrators = data.AdministratorRights.Attributes()["can_manage_administrators"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageApplications = data.AdministratorRights.Attributes()["can_manage_applications"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageSharedFolders = data.AdministratorRights.Attributes()["can_manage_shared_folders"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageBusinessUnits = data.AdministratorRights.Attributes()["can_manage_business_units"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageRouteTemplates = data.AdministratorRights.Attributes()["can_manage_route_templates"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageExternalScriptStep = data.AdministratorRights.Attributes()["can_manage_external_script_step"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageExternalScriptRootExecution = data.AdministratorRights.Attributes()["can_manage_external_script_root_execution"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageLoginRestrictionPolicies = data.AdministratorRights.Attributes()["can_manage_login_restriction_policies"].(types.Bool).ValueBool()
	bodyData.AdministratorRights.CanManageIcapSettings = data.AdministratorRights.Attributes()["can_manage_icap_settings"].(types.Bool).ValueBool()

	if len(data.BusinessUnits.Elements()) == 0 {
		bodyData.BusinessUnits = []string{}
	} else {
		for _, element := range data.BusinessUnits.Elements() {
			if str, ok := element.(types.String); ok {
				bodyData.BusinessUnits = append(bodyData.BusinessUnits, str.ValueString())
			} else {
				resp.Diagnostics.AddError(
					"Error converting BusinessUnit elements to string",
					fmt.Sprintf("Business units set: %v.", data.BusinessUnits))
				return
			}
		}
	}

	if !(data.CertificateDn.IsNull()) {
		bodyData.CertificateDn = data.CertificateDn.ValueString()
	}
	if !(data.Parent.IsNull()) {
		bodyData.Parent = data.Parent.ValueString()
	}
	if !(data.FullCreationPath.IsNull()) {
		bodyData.FullCreationPath = data.FullCreationPath.ValueString()
	}

	loginName := strings.Trim(data.LoginName.String(), "\"")
	url := fmt.Sprintf("/api/v2.0/administrators/%s/", loginName)
	_, err := r.client.CreateUpdateAPIRequest(ctx, http.MethodPut, url, bodyData, []int{204})
	if err != nil {
		resp.Diagnostics.AddError(
			"Error making API update request",
			fmt.Sprintf("Error was: %s.", err.Error()))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AdministratorsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data AdministratorsModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	loginName := strings.Trim(data.LoginName.String(), "\"")
	url := fmt.Sprintf("/api/v2.0/administrators/%s/", loginName)

	_, _, err := r.client.GenericAPIRequest(ctx, http.MethodDelete, url, nil, []int{202, 204})
	if err != nil {
		resp.Diagnostics.AddError(
			"Error making API delete request",
			fmt.Sprintf("Error was: %s.", err.Error()))
		return
	}
}

func (r *AdministratorsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
