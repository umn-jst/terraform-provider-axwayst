package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

type BusinessUnitsModel struct {
	Name                              types.String `tfsdk:"name"`
	BaseFolder                        types.String `tfsdk:"base_folder"`
	Parent                            types.String `tfsdk:"parent"`
	BusinessUnitHierarchy             types.String `tfsdk:"business_unit_hierarchy"`
	BaseFolderModifyingAllowed        types.Bool   `tfsdk:"base_folder_modifying_allowed"`
	HomeFolderModifyingAllowed        types.Bool   `tfsdk:"home_folder_modifying_allowed"`
	DMZ                               types.String `tfsdk:"dmz"`
	ManagedByCG                       types.Bool   `tfsdk:"managed_by_cg"`
	EnabledIcapServers                types.Set    `tfsdk:"enabled_icap_servers"`
	AdditionalAttributes              types.Map    `tfsdk:"additional_attributes"`
	SharedFoldersCollaborationAllowed types.Bool   `tfsdk:"shared_folders_collaboration_allowed"`
	BandwidthLimits                   types.Object `tfsdk:"bandwidth_limits"`
	HtmlTemplateSettings              types.Object `tfsdk:"html_template_settings"`
	TransfersApiSettings              types.Object `tfsdk:"transfers_api_settings"`
	AdHocSettings                     types.Object `tfsdk:"adhoc_settings"`
	FileArchivingSettings             types.Object `tfsdk:"file_archiving_settings"`
	LoginRestrictionSettings          types.Object `tfsdk:"login_restriction_settings"`
}

type BusinessUnitsAPIModel struct {
	Name                              string                             `json:"name"`
	BaseFolder                        string                             `json:"baseFolder"`
	Parent                            string                             `json:"parent,omitempty"`
	BusinessUnitHierarchy             string                             `json:"businessUnitHierarchy"`
	BaseFolderModifyingAllowed        bool                               `json:"baseFolderModifyingAllowed"`
	HomeFolderModifyingAllowed        bool                               `json:"homeFolderModifyingAllowed"`
	DMZ                               string                             `json:"dmz,omitempty"`
	ManagedByCG                       bool                               `json:"managedByCG"`
	EnabledIcapServers                []string                           `json:"enabledIcapServers,omitempty"`
	AdditionalAttributes              map[string]string                  `json:"additionalAttributes,omitempty"`
	SharedFoldersCollaborationAllowed bool                               `json:"sharedFoldersCollaborationAllowed"`
	BandwidthLimits                   BuBandwidthLimitsAPIModel          `json:"bandwidthLimits"`
	HtmlTemplateSettings              BuHtmlTemplateSettingsAPIModel     `json:"htmlTemplateSettings"`
	TransfersApiSettings              BuTransferAPISettingsAPIModel      `json:"transfersApiSettings"`
	AdHocSettings                     BuAdHocSettingsAPIModel            `json:"adHocSettings"`
	FileArchivingSettings             BuFileArchiveSettingsAPIModel      `json:"fileArchivingSettings"`
	LoginRestrictionSettings          BuLoginRestrictionSettingsAPIModel `json:"loginRestrictionSettings"`
}

type BuBandwidthLimitsAPIModel struct {
	Policy              string `json:"policy"`
	ModifyLimitsAllowed bool   `json:"modifyLimitsAllowed,omitempty"`
	InboundLimit        int32  `json:"inboundLimit,omitempty"`
	OutboundLimit       int32  `json:"outboundLimit,omitempty"`
}

type BuBandwidthLimitsModel struct {
	Policy              types.String `tfsdk:"policy"`
	ModifyLimitsAllowed types.Bool   `tfsdk:"modify_limits_allowed"`
	InboundLimit        types.Int32  `tfsdk:"inbound_limit"`
	OutboundLimit       types.Int32  `tfsdk:"outbound_limit"`
}

type BuHtmlTemplateSettingsAPIModel struct {
	HtmlTemplateFolderPath string `json:"htmlTemplateFolderPath"`
	IsAllowedForModifying  bool   `json:"isAllowedForModifying"`
}

type BuHtmlTemplateSettingsModel struct {
	HtmlTemplateFolderPath types.String `tfsdk:"html_template_folder_path"`
	IsAllowedForModifying  types.Bool   `tfsdk:"is_allowed_for_modifying"`
}

type BuTransferAPISettingsAPIModel struct {
	TransfersWebServiceAllowed         bool `json:"transfersWebServiceAllowed"`
	IsWebServiceRightsModifyingAllowed bool `json:"isWebServiceRightsModifyingAllowed"`
}

type BuTransferAPISettingsModel struct {
	TransfersWebServiceAllowed         types.Bool `tfsdk:"transfers_web_service_allowed"`
	IsWebServiceRightsModifyingAllowed types.Bool `tfsdk:"is_web_service_rights_modifying_allowed"`
}

type BuAdHocSettingsAPIModel struct {
	AuthByEmail                    bool     `json:"authByEmail,omitempty"`
	AuthByEmailModifyingAllowed    bool     `json:"authByEmailModifyingAllowed,omitempty"`
	DeliveryMethodModifyingAllowed bool     `json:"deliveryMethodModifyingAllowed,omitempty"`
	DeliveryMethod                 string   `json:"deliveryMethod,omitempty"`
	EnrollmentTypes                []string `json:"enrollmentTypes,omitempty"`
	ImplicitEnrollmentType         string   `json:"implicitEnrollmentType,omitempty"`
	EnrollmentTemplate             string   `json:"enrollmentTemplate,omitempty"`
	NotificationTemplate           string   `json:"notificationTemplate,omitempty"`
}

type BuAdHocSettingsModel struct {
	AuthByEmail                    types.Bool   `tfsdk:"auth_by_email"`
	AuthByEmailModifyingAllowed    types.Bool   `tfsdk:"auth_by_email_modifying_allowed"`
	DeliveryMethodModifyingAllowed types.Bool   `tfsdk:"delivery_method_modifying_allowed"`
	DeliveryMethod                 types.String `tfsdk:"delivery_method"`
	EnrollmentTypes                types.Set    `tfsdk:"enrollment_types"`
	ImplicitEnrollmentType         types.String `tfsdk:"implicit_enrollment_type"`
	EnrollmentTemplate             types.String `tfsdk:"enrollment_template"`
	NotificationTemplate           types.String `tfsdk:"notification_template"`
}

type BuFileArchiveSettingsAPIModel struct {
	Policy                      string `json:"policy,omitempty"`
	FolderPolicy                string `json:"folderPolicy,omitempty"`
	EncryptionCertificatePolicy string `json:"encryptionCertificatePolicy,omitempty"`
	CustomFileSizePolicy        string `json:"customFileSizePolicy,omitempty"`
	CustomFileSize              int32  `json:"customFileSize,omitempty"`
	PolicyModifyingAllowed      bool   `json:"policyModifyingAllowed,omitempty"`
	CustomFolder                string `json:"customFolder,omitempty"`
	CustomEncryptionCertificate string `json:"customEncryptionCertificate,omitempty"`
}

type BuFileArchiveSettingsModel struct {
	Policy                      types.String `tfsdk:"policy"`
	FolderPolicy                types.String `tfsdk:"folder_policy"`
	EncryptionCertificatePolicy types.String `tfsdk:"encryption_certificate_policy"`
	CustomFileSizePolicy        types.String `tfsdk:"custom_file_size_policy"`
	CustomFileSize              types.Int32  `tfsdk:"custom_file_size"`
	PolicyModifyingAllowed      types.Bool   `tfsdk:"policy_modifying_allowed"`
	CustomFolder                types.String `tfsdk:"custom_folder"`
	CustomEncryptionCertificate types.String `tfsdk:"custom_encryption_certificate"`
}

type BuLoginRestrictionSettingsAPIModel struct {
	Policy                   string `json:"policy,omitempty"`
	IsPolicyModifyingAllowed bool   `json:"isPolicyModifyingAllowed,omitempty"`
}

type BuLoginRestrictionSettingsModel struct {
	Policy                   types.String `tfsdk:"policy"`
	IsPolicyModifyingAllowed types.Bool   `tfsdk:"is_policy_modifying_allowed"`
}

// Used by the resource_business_units.go in the Create() and Update() functions to move data from a TF object to a JSON object.
func businessUnitDataPopulate(ctx context.Context, data BusinessUnitsModel) (bodyData BusinessUnitsAPIModel, diags diag.Diagnostics) {

	bodyData.Name = data.Name.ValueString()
	bodyData.BaseFolder = data.BaseFolder.ValueString()
	bodyData.Parent = data.Parent.ValueString()
	bodyData.BusinessUnitHierarchy = data.BusinessUnitHierarchy.ValueString()
	bodyData.BaseFolderModifyingAllowed = data.BaseFolderModifyingAllowed.ValueBool()
	bodyData.HomeFolderModifyingAllowed = data.HomeFolderModifyingAllowed.ValueBool()
	bodyData.DMZ = data.DMZ.ValueString()
	bodyData.ManagedByCG = data.ManagedByCG.ValueBool()

	var additionalAttr map[string]string
	diags = data.AdditionalAttributes.ElementsAs(ctx, &additionalAttr, false)
	if diags.HasError() {
		return
	}

	if len(additionalAttr) > 0 {
		bodyData.AdditionalAttributes = additionalAttr
	}

	var icapServers []string
	diags = data.EnabledIcapServers.ElementsAs(ctx, &icapServers, false)
	if diags.HasError() {
		return
	}

	// if len(icapServers) > 0 {
	bodyData.EnabledIcapServers = icapServers
	// }

	var bandwidthData BuBandwidthLimitsModel
	diags = data.BandwidthLimits.As(ctx, &bandwidthData, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	bodyData.BandwidthLimits.Policy = bandwidthData.Policy.ValueString()
	bodyData.BandwidthLimits.ModifyLimitsAllowed = bandwidthData.ModifyLimitsAllowed.ValueBool()
	bodyData.BandwidthLimits.InboundLimit = bandwidthData.InboundLimit.ValueInt32()
	bodyData.BandwidthLimits.OutboundLimit = bandwidthData.OutboundLimit.ValueInt32()

	var htmlSettings BuHtmlTemplateSettingsModel

	diags = data.HtmlTemplateSettings.As(ctx, &htmlSettings, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	bodyData.HtmlTemplateSettings.HtmlTemplateFolderPath = htmlSettings.HtmlTemplateFolderPath.ValueString()
	bodyData.HtmlTemplateSettings.IsAllowedForModifying = htmlSettings.IsAllowedForModifying.ValueBool()

	var transferAPISettings BuTransferAPISettingsModel

	diags = data.TransfersApiSettings.As(ctx, &transferAPISettings, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	bodyData.TransfersApiSettings.TransfersWebServiceAllowed = transferAPISettings.TransfersWebServiceAllowed.ValueBool()
	bodyData.TransfersApiSettings.IsWebServiceRightsModifyingAllowed = transferAPISettings.IsWebServiceRightsModifyingAllowed.ValueBool()

	var adhocSettings BuAdHocSettingsModel

	diags = data.AdHocSettings.As(ctx, &adhocSettings, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	bodyData.AdHocSettings.AuthByEmail = adhocSettings.AuthByEmail.ValueBool()
	bodyData.AdHocSettings.AuthByEmailModifyingAllowed = adhocSettings.AuthByEmailModifyingAllowed.ValueBool()
	bodyData.AdHocSettings.DeliveryMethodModifyingAllowed = adhocSettings.DeliveryMethodModifyingAllowed.ValueBool()
	bodyData.AdHocSettings.DeliveryMethod = adhocSettings.DeliveryMethod.ValueString()
	bodyData.AdHocSettings.ImplicitEnrollmentType = adhocSettings.ImplicitEnrollmentType.ValueString()
	bodyData.AdHocSettings.EnrollmentTemplate = adhocSettings.EnrollmentTemplate.ValueString()
	bodyData.AdHocSettings.NotificationTemplate = adhocSettings.NotificationTemplate.ValueString()

	var enrlTypes []string
	diags = adhocSettings.EnrollmentTypes.ElementsAs(ctx, &enrlTypes, false)
	if diags.HasError() {
		return
	}
	bodyData.AdHocSettings.EnrollmentTypes = enrlTypes

	var fileArchiveSettings BuFileArchiveSettingsModel

	diags = data.FileArchivingSettings.As(ctx, &fileArchiveSettings, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	bodyData.FileArchivingSettings.Policy = fileArchiveSettings.Policy.ValueString()
	bodyData.FileArchivingSettings.FolderPolicy = fileArchiveSettings.FolderPolicy.ValueString()
	bodyData.FileArchivingSettings.EncryptionCertificatePolicy = fileArchiveSettings.EncryptionCertificatePolicy.ValueString()
	bodyData.FileArchivingSettings.CustomFileSizePolicy = fileArchiveSettings.CustomFileSizePolicy.ValueString()
	bodyData.FileArchivingSettings.CustomFileSize = fileArchiveSettings.CustomFileSize.ValueInt32()
	bodyData.FileArchivingSettings.PolicyModifyingAllowed = fileArchiveSettings.PolicyModifyingAllowed.ValueBool()
	bodyData.FileArchivingSettings.CustomFolder = fileArchiveSettings.CustomFolder.ValueString()
	bodyData.FileArchivingSettings.CustomEncryptionCertificate = fileArchiveSettings.CustomEncryptionCertificate.ValueString()

	var loginRestrictions BuLoginRestrictionSettingsModel

	diags = data.LoginRestrictionSettings.As(ctx, &loginRestrictions, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	bodyData.LoginRestrictionSettings.Policy = loginRestrictions.Policy.ValueString()
	bodyData.LoginRestrictionSettings.IsPolicyModifyingAllowed = loginRestrictions.IsPolicyModifyingAllowed.ValueBool()

	return
}
