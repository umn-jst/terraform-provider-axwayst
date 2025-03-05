package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int32default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &BusinessUnitsResource{}

var _ resource.ResourceWithImportState = &BusinessUnitsResource{}

func NewBusinessUnitsResource() resource.Resource {
	return &BusinessUnitsResource{}
}

type BusinessUnitsResource struct {
	client *AxwaySTClient
}

func (r *BusinessUnitsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_business_units"
}

func (r *BusinessUnitsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: ``,
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The unique name of the business unit entity.",
			},
			"base_folder": schema.StringAttribute{
				Required:    true,
				Description: "The base folder of the business unit entity.",
			},
			"parent": schema.StringAttribute{
				Optional:    true,
				Description: "The name of the parent business unit entity.",
			},
			"business_unit_hierarchy": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The full path hierarchy of the business unit entity.",
			},
			"base_folder_modifying_allowed": schema.BoolAttribute{
				Optional:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Flag indicating if the base folder of the business unit entity is modifiable (this property defines whether the base folder for the belonging accounts may be modified).",
				Computed:    true,
			},
			"home_folder_modifying_allowed": schema.BoolAttribute{
				Optional:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Flag indicating if the belonging accounts' base folders are modifiable.",
				Computed:    true,
			},
			"dmz": schema.StringAttribute{
				Description: "The name of the DMZ zone",
				Optional:    true,
			},
			"managed_by_cg": schema.BoolAttribute{
				Optional:    true,
				Description: "This property indicates whether the business unit is managed by Central Governance.",
			},
			"enabled_icap_servers": schema.SetAttribute{
				Optional:    true,
				Description: "Enabled icap servers of the business unit.",
				ElementType: types.StringType,
				Default: setdefault.StaticValue(
					types.SetValueMust(
						types.StringType,
						[]attr.Value{},
					),
				),
				Computed: true,
			},
			"shared_folders_collaboration_allowed": schema.BoolAttribute{
				Optional:    true,
				Description: "Flag indicating if accounts may collaborate using, creating and sharing folders.",
			},
			"additional_attributes": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: `Additional attributes which are defined with "key": "value" pairs. Keys must start with "userVars." prefix, follow the pattern: [a-zA-Z0-9_.]+ and have length between 10 and 255 characters (including the prefix). Non prefixed part of key should not start with "userVars.", since it is a reserved word. Both key and value cannot be blank.`,
			},
			"bandwidth_limits": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"policy": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Bandwidth policy.",
						Default:     stringdefault.StaticString("default"),
						Validators:  []validator.String{stringvalidator.OneOf("default", "custom", "disabled")},
					},
					"modify_limits_allowed": schema.BoolAttribute{
						Description: "Whether modifying limits is allowed.",
						Optional:    true,
					},
					"inbound_limit": schema.Int32Attribute{
						Optional:    true,
						Description: "Bandwidth's inbound limit.",
					},
					"outbound_limit": schema.Int32Attribute{
						Optional:    true,
						Description: "Bandwidth's outbound limit.",
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"policy":                types.StringType,
							"modify_limits_allowed": types.BoolType,
							"inbound_limit":         types.Int32Type,
							"outbound_limit":        types.Int32Type,
						},
						map[string]attr.Value{
							"policy":                types.StringValue("default"),
							"modify_limits_allowed": types.BoolNull(),
							"inbound_limit":         types.Int32Null(),
							"outbound_limit":        types.Int32Null(),
						},
					),
				),
			},
			"html_template_settings": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"html_template_folder_path": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Description: "The HTML template directory path on the local system used for this business unit entity",
						Default:     stringdefault.StaticString("Default HTML Template"),
						Validators:  []validator.String{stringvalidator.OneOf("Default HTML Template", "ST Web Client")},
					},
					"is_allowed_for_modifying": schema.BoolAttribute{
						Description: "Flag indicating if the HTML Template folder may be modified",
						Optional:    true,
						Default:     booldefault.StaticBool(false),
						Computed:    true,
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"html_template_folder_path": types.StringType,
							"is_allowed_for_modifying":  types.BoolType,
						},
						map[string]attr.Value{
							"html_template_folder_path": types.StringValue("Default HTML Template"),
							"is_allowed_for_modifying":  types.BoolValue(false),
						},
					),
				),
			},
			"transfers_api_settings": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"transfers_web_service_allowed": schema.BoolAttribute{
						Description: "Defines whether the access to the /transfers resource from the End-user REST API is allowed",
						Optional:    true,
					},
					"is_web_service_rights_modifying_allowed": schema.BoolAttribute{
						Description: "Flag indicating if web services rights are allowed for modifying",
						Optional:    true,
						Default:     booldefault.StaticBool(false),
						Computed:    true,
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"transfers_web_service_allowed":           types.BoolType,
							"is_web_service_rights_modifying_allowed": types.BoolType,
						},
						map[string]attr.Value{
							"transfers_web_service_allowed":           types.BoolNull(),
							"is_web_service_rights_modifying_allowed": types.BoolValue(false),
						},
					),
				),
			},
			"adhoc_settings": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"auth_by_email": schema.BoolAttribute{
						Description: "Flag indicating if auth is by email",
						Optional:    true,
						Default:     booldefault.StaticBool(false),
						Computed:    true,
					},
					"auth_by_email_modifying_allowed": schema.BoolAttribute{
						Description: "Flag indicating if auth by email is allowed for modifying",
						Optional:    true,
						Default:     booldefault.StaticBool(false),
						Computed:    true,
					},
					"delivery_method_modifying_allowed": schema.BoolAttribute{
						Description: "Flag indicating if the belonging accounts' could enroll other accounts",
						Optional:    true,
						Default:     booldefault.StaticBool(false),
						Computed:    true,
					},
					"delivery_method": schema.StringAttribute{
						Description: `This property defines the delivery method. When deliveryMethod is set to 'Disabled' then Adhoc is disabled and enrollmentType/implicitEnrollmentType can not be set. When deliveryMethod is set to 'Default' then it is only available on BU and Account (setting the BU to use the value and account to use the BU value). When deliveryMethod is set to 'Anonymous' then implicit enrollment types 'Anonymous' and "" (Select by sender) are enabled. When deliveryMethod is set to 'Account Without Enrollment' then implicit enrollment types 'Anonymous', ""  (Select by sender) and 'Existing Account' are enabled. When deliveryMethod is set to 'Account With Enrollment' then implicit enrollment types 'Anonymous', "" (Select by sender), 'Enroll unlicensed', 'Enroll licensed' are enabled`,
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString("DEFAULT"),
						Validators:  []validator.String{stringvalidator.OneOf("DEFAULT", "DISABLED", "ANONYMOUS", "ACCOUNT_WITHOUT_ENROLLMENT", "ACCOUNT_WITH_ENROLLMENT", "CUSTOM")},
					},
					"enrollment_types": schema.SetAttribute{
						Optional:    true,
						Description: "This property is used for a custom delivery method and can be set only if deliveryMethod property is set to 'Custom'.",
						ElementType: types.StringType,
						Default: setdefault.StaticValue(
							types.SetValueMust(
								types.StringType,
								[]attr.Value{},
							),
						),
						Computed: true,
					},
					"implicit_enrollment_type": schema.StringAttribute{
						Optional:    true,
						Description: `The Implicit Enrollment Type value of the business unit entity. This property controls which option Web Access Plus selects initially in the User Access window and which enrollment type is used by the Axway Email Plug-ins. The choices depend on the enrollment types enabled by the Delivery Methods and Enrollment Types fields`,
						Validators:  []validator.String{stringvalidator.OneOf("ANONYMOUS_LINK", "CHALLENGED_LINK", "EXISTING_ACCOUNT", "ENROLL_UNLICENSED", "ENROLL_LICENSED", "ENROLL_MOBILE")},
					},
					"enrollment_template": schema.StringAttribute{
						Optional:    true,
						Description: "The name of the notification template for this business unit entity",
						Computed:    true,
						Default:     stringdefault.StaticString("default"),
					},
					"notification_template": schema.StringAttribute{
						Description: "The notification template",
						Optional:    true,
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"auth_by_email":                     types.BoolType,
							"auth_by_email_modifying_allowed":   types.BoolType,
							"delivery_method_modifying_allowed": types.BoolType,
							"delivery_method":                   types.StringType,
							"enrollment_types":                  types.SetType{ElemType: types.StringType},
							"implicit_enrollment_type":          types.StringType,
							"enrollment_template":               types.StringType,
							"notification_template":             types.StringType,
						},
						map[string]attr.Value{
							"auth_by_email":                     types.BoolValue(false),
							"auth_by_email_modifying_allowed":   types.BoolValue(false),
							"delivery_method_modifying_allowed": types.BoolValue(false),
							"delivery_method":                   types.StringValue("DEFAULT"),
							"enrollment_types":                  types.SetNull(types.StringType),
							"implicit_enrollment_type":          types.StringNull(),
							"enrollment_template":               types.StringValue("default"),
							"notification_template":             types.StringNull(),
						},
					),
				),
			},
			"file_archiving_settings": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"policy": schema.StringAttribute{
						Description: "Defines whether the child business units are allowed to modify archiving policy",
						Optional:    true,
						Default:     stringdefault.StaticString("default"),
						Computed:    true,
						Validators:  []validator.String{stringvalidator.OneOf("default", "enabled", "disabled")},
					},
					"policy_modifying_allowed": schema.BoolAttribute{
						Description: " Defines whether the child business units are allowed to modify archiving policy.",
						Optional:    true,
						Default:     booldefault.StaticBool(false),
						Computed:    true,
					},
					"folder_policy": schema.StringAttribute{
						Description: "Defines whether account under BU can modify folder.",
						Optional:    true,
						Default:     stringdefault.StaticString("default"),
						Computed:    true,
						Validators:  []validator.String{stringvalidator.OneOf("default", "custom")},
					},
					"custom_folder": schema.StringAttribute{
						Description: "Custom archiving folder of the business unit",
						Optional:    true,
						Default:     stringdefault.StaticString(""),
						Computed:    true,
					},
					"encryption_certificate_policy": schema.StringAttribute{
						Description: "Archiving certificate policy of the business unit.",
						Optional:    true,
						Default:     stringdefault.StaticString("default"),
						Computed:    true,
					},
					"custom_encryption_certificate": schema.StringAttribute{
						Description: "Custom encryption certificate of the business unit.",
						Optional:    true,
					},
					"custom_file_size_policy": schema.StringAttribute{
						Description: "Custom file size policy of the business unit.",
						Optional:    true,
						Default:     stringdefault.StaticString("default"),
						Computed:    true,
						Validators:  []validator.String{stringvalidator.OneOf("default", "custom")},
					},
					"custom_file_size": schema.Int32Attribute{
						Description: "Custom file size for archiving of the businessunit unit.",
						Default:     int32default.StaticInt32(0),
						Computed:    true,
						Optional:    true,
						Validators:  []validator.Int32{int32validator.AtLeast(0)},
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"policy":                        types.StringType,
							"folder_policy":                 types.StringType,
							"encryption_certificate_policy": types.StringType,
							"custom_file_size_policy":       types.StringType,
							"custom_file_size":              types.Int32Type,
							"policy_modifying_allowed":      types.BoolType,
							"custom_folder":                 types.StringType,
							"custom_encryption_certificate": types.StringType,
						},
						map[string]attr.Value{
							"policy":                        types.StringValue("default"),
							"folder_policy":                 types.StringValue("default"),
							"encryption_certificate_policy": types.StringValue("default"),
							"custom_file_size_policy":       types.StringValue("default"),
							"custom_file_size":              types.Int32Value(0),
							"policy_modifying_allowed":      types.BoolValue(false),
							"custom_folder":                 types.StringValue(""),
							"custom_encryption_certificate": types.StringNull(),
						},
					),
				),
			},
			"login_restriction_settings": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"policy": schema.StringAttribute{
						Description: "The login restriction policy for this business unit.",
						Optional:    true,
					},
					"is_policy_modifying_allowed": schema.BoolAttribute{
						Description: "Flag indicating whether the login restriction policy option is modifiable on account level.",
						Optional:    true,
						Default:     booldefault.StaticBool(false),
						Computed:    true,
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"policy":                      types.StringType,
							"is_policy_modifying_allowed": types.BoolType,
						},
						map[string]attr.Value{
							"policy":                      types.StringNull(),
							"is_policy_modifying_allowed": types.BoolValue(false),
						},
					),
				),
			},
		},
	}
}

func (r *BusinessUnitsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *BusinessUnitsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data BusinessUnitsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var bodyData BusinessUnitsAPIModel

	bodyData.Name = data.Name.ValueString()
	bodyData.BaseFolder = data.BaseFolder.ValueString()
	bodyData.Parent = data.Parent.ValueString()
	bodyData.BusinessUnitHierarchy = data.BusinessUnitHierarchy.ValueString()
	bodyData.BaseFolderModifyingAllowed = data.BaseFolderModifyingAllowed.ValueBool()
	bodyData.HomeFolderModifyingAllowed = data.HomeFolderModifyingAllowed.ValueBool()
	bodyData.DMZ = data.DMZ.ValueString()
	bodyData.ManagedByCG = data.ManagedByCG.ValueBool()

	additionalAttr := make(map[string]string, len(data.AdditionalAttributes.Elements()))
	resp.Diagnostics.Append(data.AdditionalAttributes.ElementsAs(ctx, &additionalAttr, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(additionalAttr) > 0 {
		bodyData.AdditionalAttributes = additionalAttr
	}

	icapServers := make([]string, 0, len(data.EnabledIcapServers.Elements()))
	resp.Diagnostics.Append(data.EnabledIcapServers.ElementsAs(ctx, &icapServers, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(icapServers) > 0 {
		bodyData.EnabledIcapServers = icapServers
	}
	bodyData.BandwidthLimits.Policy = data.BandwidthLimits.Attributes()["policy"].(types.String).ValueString()
	bodyData.BandwidthLimits.ModifyLimitsAllowed = data.BandwidthLimits.Attributes()["modify_limits_allowed"].(types.Bool).ValueBool()
	bodyData.BandwidthLimits.InboundLimit = data.BandwidthLimits.Attributes()["inbound_limit"].(types.Int32).ValueInt32()
	bodyData.BandwidthLimits.OutboundLimit = data.BandwidthLimits.Attributes()["outbound_limit"].(types.Int32).ValueInt32()

	bodyData.HtmlTemplateSettings.HtmlTemplateFolderPath = data.HtmlTemplateSettings.Attributes()["html_template_folder_path"].(types.String).ValueString()
	bodyData.HtmlTemplateSettings.IsAllowedForModifying = data.HtmlTemplateSettings.Attributes()["is_allowed_for_modifying"].(types.Bool).ValueBool()

	bodyData.TransfersApiSettings.IsWebServiceRightsModifyingAllowed = data.TransfersApiSettings.Attributes()["is_web_service_rights_modifying_allowed"].(types.Bool).ValueBool()
	bodyData.TransfersApiSettings.TransfersWebServiceAllowed = data.TransfersApiSettings.Attributes()["transfers_web_service_allowed"].(types.Bool).ValueBool()

	bodyData.AdHocSettings.AuthByEmail = data.AdHocSettings.Attributes()["auth_by_email"].(types.Bool).ValueBool()
	bodyData.AdHocSettings.AuthByEmailModifyingAllowed = data.AdHocSettings.Attributes()["auth_by_email_modifying_allowed"].(types.Bool).ValueBool()
	bodyData.AdHocSettings.DeliveryMethodModifyingAllowed = data.AdHocSettings.Attributes()["delivery_method_modifying_allowed"].(types.Bool).ValueBool()
	bodyData.AdHocSettings.DeliveryMethod = data.AdHocSettings.Attributes()["delivery_method"].(types.String).ValueString()

	var enrlTypes []string

	resp.Diagnostics.Append(data.AdHocSettings.Attributes()["enrollment_types"].(types.Set).ElementsAs(ctx, &enrlTypes, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	bodyData.AdHocSettings.EnrollmentTypes = enrlTypes

	bodyData.AdHocSettings.ImplicitEnrollmentType = data.AdHocSettings.Attributes()["implicit_enrollment_type"].(types.String).ValueString()
	bodyData.AdHocSettings.EnrollmentTemplate = data.AdHocSettings.Attributes()["enrollment_template"].(types.String).ValueString()
	bodyData.AdHocSettings.NotificationTemplate = data.AdHocSettings.Attributes()["notification_template"].(types.String).ValueString()

	bodyData.FileArchivingSettings.Policy = data.FileArchivingSettings.Attributes()["policy"].(types.String).ValueString()
	bodyData.FileArchivingSettings.PolicyModifyingAllowed = data.FileArchivingSettings.Attributes()["policy_modifying_allowed"].(types.Bool).ValueBool()
	bodyData.FileArchivingSettings.FolderPolicy = data.FileArchivingSettings.Attributes()["folder_policy"].(types.String).ValueString()
	bodyData.FileArchivingSettings.CustomFolder = data.FileArchivingSettings.Attributes()["custom_folder"].(types.String).ValueString()
	bodyData.FileArchivingSettings.EncryptionCertificatePolicy = data.FileArchivingSettings.Attributes()["encryption_certificate_policy"].(types.String).ValueString()
	bodyData.FileArchivingSettings.CustomEncryptionCertificate = data.FileArchivingSettings.Attributes()["custom_encryption_certificate"].(types.String).ValueString()
	bodyData.FileArchivingSettings.CustomFileSizePolicy = data.FileArchivingSettings.Attributes()["custom_file_size_policy"].(types.String).ValueString()
	bodyData.FileArchivingSettings.CustomFileSize = data.FileArchivingSettings.Attributes()["custom_file_size"].(types.Int32).ValueInt32()

	bodyData.LoginRestrictionSettings.IsPolicyModifyingAllowed = data.LoginRestrictionSettings.Attributes()["is_policy_modifying_allowed"].(types.Bool).ValueBool()
	bodyData.LoginRestrictionSettings.Policy = data.LoginRestrictionSettings.Attributes()["policy"].(types.String).ValueString()

	url := "/api/v2.0/businessUnits/"
	_, err := r.client.CreateUpdateAPIRequest(ctx, http.MethodPost, url, bodyData, []int{201})
	if err != nil {
		resp.Diagnostics.AddError(
			"Error making API http request",
			fmt.Sprintf("Error was: %s.", err.Error()))
		return
	}

	if data.BusinessUnitHierarchy.IsUnknown() {
		data.BusinessUnitHierarchy = data.Name
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *BusinessUnitsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data BusinessUnitsModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("/api/v2.0/businessUnits/%s/", data.Name.ValueString())

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

	var responseData BusinessUnitsAPIModel

	err = json.Unmarshal(body, &responseData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to unmarshal json",
			fmt.Sprintf("bodyData: %+v.", body))
		return
	}

	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), responseData.LoginName)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role_name"), responseData.RoleName)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("is_limited"), responseData.IsLimited)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("local_authentication"), responseData.LocalAuthentication)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("dual_authentication"), responseData.DualAuthentication)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("locked"), responseData.Locked)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("business_units"), responseData.BusinessUnits)...)

	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("password_credentials").AtName("password_expired"), responseData.PasswordCredentials.PasswordExpired)...)

	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_read_only"), responseData.AdministratorRights.CanReadOnly)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("is_maker"), responseData.AdministratorRights.IsMaker)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("is_checker"), responseData.AdministratorRights.IsChecker)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_create_users"), responseData.AdministratorRights.CanCreateUsers)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_update_users"), responseData.AdministratorRights.CanUpdateUsers)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_access_help_desk"), responseData.AdministratorRights.CanAccessHelpDesk)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_see_full_audit_log"), responseData.AdministratorRights.CanSeeFullAuditLog)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_administrators"), responseData.AdministratorRights.CanManageAdministrators)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_applications"), responseData.AdministratorRights.CanManageApplications)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_shared_folders"), responseData.AdministratorRights.CanManageSharedFolders)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_business_units"), responseData.AdministratorRights.CanManageBusinessUnits)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_route_templates"), responseData.AdministratorRights.CanManageRouteTemplates)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_external_script_step"), responseData.AdministratorRights.CanManageExternalScriptStep)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_external_script_root_execution"), responseData.AdministratorRights.CanManageExternalScriptRootExecution)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_login_restriction_policies"), responseData.AdministratorRights.CanManageLoginRestrictionPolicies)...)
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("administrator_rights").AtName("can_manage_icap_settings"), responseData.AdministratorRights.CanManageIcapSettings)...)

	// if !(data.CertificateDn.IsNull() && responseData.CertificateDn == "") {
	// 	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("certificate_dn"), responseData.CertificateDn)...)
	// 	if resp.Diagnostics.HasError() {
	// 		return
	// 	}
	// }

	// if !(data.Parent.IsNull() && responseData.Parent == "") {
	// 	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("parent"), responseData.Parent)...)
	// 	if resp.Diagnostics.HasError() {
	// 		return
	// 	}
	// }

	// if !(data.FullCreationPath.IsNull() && responseData.FullCreationPath == "") {
	// 	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("full_creation_path"), responseData.FullCreationPath)...)
	// 	if resp.Diagnostics.HasError() {
	// 		return
	// 	}
	// }

	// // Always use current state of password to set resp.State as responseData.Password will not be valid
	// var statePassword types.String
	// diags := req.State.GetAttribute(ctx, path.Root("password_credentials").AtName("password"), &statePassword)
	// if diags.HasError() {
	// 	return
	// }
	// resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("password_credentials").AtName("password"), statePassword)...)
}

func (r *BusinessUnitsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data BusinessUnitsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// var bodyData BusinessUnitsAPIModel

	// bodyData.LoginName = data.LoginName.ValueString()
	// bodyData.RoleName = data.RoleName.ValueString()
	// bodyData.IsLimited = data.IsLimited.ValueBool()
	// bodyData.LocalAuthentication = data.LocalAuthentication.ValueBool()
	// bodyData.DualAuthentication = data.DualAuthentication.ValueBool()
	// bodyData.Locked = data.Locked.ValueBool()

	// bodyData.PasswordCredentials.Password = data.PasswordCredentials.Attributes()["password"].(types.String).ValueString()
	// bodyData.PasswordCredentials.PasswordExpired = data.PasswordCredentials.Attributes()["password_expired"].(types.Bool).ValueBool()

	// bodyData.AdministratorRights.CanReadOnly = data.AdministratorRights.Attributes()["can_read_only"].(types.Bool).ValueBool()
	// bodyData.AdministratorRights.IsMaker = data.AdministratorRights.Attributes()["is_maker"].(types.Bool).ValueBool()
	// bodyData.AdministratorRights.IsChecker = data.AdministratorRights.Attributes()["is_checker"].(types.Bool).ValueBool()
	// bodyData.AdministratorRights.CanCreateUsers = data.AdministratorRights.Attributes()["can_create_users"].(types.Bool).ValueBool()
	// bodyData.AdministratorRights.CanUpdateUsers = data.AdministratorRights.Attributes()["can_update_users"].(types.Bool).ValueBool()
	// bodyData.AdministratorRights.CanAccessHelpDesk = data.AdministratorRights.Attributes()["can_access_help_desk"].(types.Bool).ValueBool()
	// bodyData.AdministratorRights.CanSeeFullAuditLog = data.AdministratorRights.Attributes()["can_see_full_audit_log"].(types.Bool).ValueBool()
	// bodyData.AdministratorRights.CanManageAdministrators = data.AdministratorRights.Attributes()["can_manage_administrators"].(types.Bool).ValueBool()
	// bodyData.AdministratorRights.CanManageApplications = data.AdministratorRights.Attributes()["can_manage_applications"].(types.Bool).ValueBool()
	// bodyData.AdministratorRights.CanManageSharedFolders = data.AdministratorRights.Attributes()["can_manage_shared_folders"].(types.Bool).ValueBool()
	// bodyData.AdministratorRights.CanManageBusinessUnits = data.AdministratorRights.Attributes()["can_manage_business_units"].(types.Bool).ValueBool()
	// bodyData.AdministratorRights.CanManageRouteTemplates = data.AdministratorRights.Attributes()["can_manage_route_templates"].(types.Bool).ValueBool()
	// bodyData.AdministratorRights.CanManageExternalScriptStep = data.AdministratorRights.Attributes()["can_manage_external_script_step"].(types.Bool).ValueBool()
	// bodyData.AdministratorRights.CanManageExternalScriptRootExecution = data.AdministratorRights.Attributes()["can_manage_external_script_root_execution"].(types.Bool).ValueBool()
	// bodyData.AdministratorRights.CanManageLoginRestrictionPolicies = data.AdministratorRights.Attributes()["can_manage_login_restriction_policies"].(types.Bool).ValueBool()
	// bodyData.AdministratorRights.CanManageIcapSettings = data.AdministratorRights.Attributes()["can_manage_icap_settings"].(types.Bool).ValueBool()

	// if len(data.BusinessUnits.Elements()) == 0 {
	// 	bodyData.BusinessUnits = []string{}
	// } else {
	// 	for _, element := range data.BusinessUnits.Elements() {
	// 		if str, ok := element.(types.String); ok {
	// 			bodyData.BusinessUnits = append(bodyData.BusinessUnits, str.ValueString())
	// 		} else {
	// 			resp.Diagnostics.AddError(
	// 				"Error converting BusinessUnit elements to string",
	// 				fmt.Sprintf("Business units set: %v.", data.BusinessUnits))
	// 			return
	// 		}
	// 	}
	// }

	// if !(data.CertificateDn.IsNull()) {
	// 	bodyData.CertificateDn = data.CertificateDn.ValueString()
	// }
	// if !(data.Parent.IsNull()) {
	// 	bodyData.Parent = data.Parent.ValueString()
	// }
	// if !(data.FullCreationPath.IsNull()) {
	// 	bodyData.FullCreationPath = data.FullCreationPath.ValueString()
	// }

	// loginName := strings.Trim(data.LoginName.String(), "\"")
	// url := fmt.Sprintf("/api/v2.0/administrators/%s/", loginName)
	// _, err := r.client.CreateUpdateAPIRequest(ctx, http.MethodPut, url, bodyData, []int{204})
	// if err != nil {
	// 	resp.Diagnostics.AddError(
	// 		"Error making API update request",
	// 		fmt.Sprintf("Error was: %s.", err.Error()))
	// 	return
	// }

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *BusinessUnitsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data BusinessUnitsModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("/api/v2.0/businessUnits/%s/", data.Name.ValueString())

	_, _, err := r.client.GenericAPIRequest(ctx, http.MethodDelete, url, nil, []int{204})
	if err != nil {
		resp.Diagnostics.AddError(
			"Error making API delete request",
			fmt.Sprintf("Error was: %s.", err.Error()))
		return
	}
}

func (r *BusinessUnitsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
}
