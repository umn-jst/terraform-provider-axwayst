package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
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
}

type BusinessUnitsAPIModel struct {
	Name                              string                         `json:"name"`
	BaseFolder                        string                         `json:"baseFolder"`
	Parent                            string                         `json:"parent"`
	BusinessUnitHierarchy             string                         `json:"businessUnitHierarchy"`
	BaseFolderModifyingAllowed        bool                           `json:"baseFolderModifyingAllowed"`
	HomeFolderModifyingAllowed        bool                           `json:"homeFolderModifyingAllowed"`
	DMZ                               string                         `json:"dmz"`
	ManagedByCG                       bool                           `json:"managedByCG"`
	EnabledIcapServers                []string                       `json:"enabledIcapServers,omitempty"`
	AdditionalAttributes              map[string]string              `json:"additionalAttributes,omitempty"`
	SharedFoldersCollaborationAllowed bool                           `json:"sharedFoldersCollaborationAllowed"`
	BandwidthLimits                   BuBandwidthLimitsAPIModel      `json:"bandwidthLimits"`
	HtmlTemplateSettings              BuHtmlTemplateSettingsAPIModel `json:"htmlTemplateSettings"`
	TransfersApiSettings              BuTransferAPISettingsAPIModel  `json:"transfersApiSettings"`
	AdHocSettings                     BuAdHocSettingsAPIModel        `json:"adHocSettings"`
}

type BuBandwidthLimitsAPIModel struct {
	Policy              string `json:"policy"`
	ModifyLimitsAllowed bool   `json:"modifyLimitsAllowed,omitempty"`
	InboundLimit        int32  `json:"inboundLimit,omitempty"`
	OutboundLimit       int32  `json:"outboundLimit,omitempty"`
}

type BuHtmlTemplateSettingsAPIModel struct {
	HtmlTemplateFolderPath string `json:"htmlTemplateFolderPath"`
	IsAllowedForModifying  bool   `json:"isAllowedForModifying"`
}

type BuTransferAPISettingsAPIModel struct {
	TransfersWebServiceAllowed         bool `json:"transfersWebServiceAllowed"`
	IsWebServiceRightsModifyingAllowed bool `json:"isWebServiceRightsModifyingAllowed"`
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

type AdministratorsModel struct {
	AdministratorRights types.Object `tfsdk:"administrator_rights"`
	BusinessUnits       types.Set    `tfsdk:"business_units"`
	CertificateDn       types.String `tfsdk:"certificate_dn"`
	DualAuthentication  types.Bool   `tfsdk:"dual_authentication"`
	FullCreationPath    types.String `tfsdk:"full_creation_path"`
	IsLimited           types.Bool   `tfsdk:"is_limited"`
	LocalAuthentication types.Bool   `tfsdk:"local_authentication"`
	Locked              types.Bool   `tfsdk:"locked"`
	LoginName           types.String `tfsdk:"id"`
	Parent              types.String `tfsdk:"parent"`
	PasswordCredentials types.Object `tfsdk:"password_credentials"`
	RoleName            types.String `tfsdk:"role_name"`
}

type AdministratorsAPIModel struct {
	AdministratorRights AdministratorsRightsAPIModel             `json:"administratorRights"`
	BusinessUnits       []string                                 `json:"businessUnits"`
	CertificateDn       string                                   `json:"certificateDN"`
	DualAuthentication  bool                                     `json:"dualAuthentication"`
	FullCreationPath    string                                   `json:"fullCreationPath"`
	IsLimited           bool                                     `json:"isLimited"`
	LocalAuthentication bool                                     `json:"localAuthentication"`
	Locked              bool                                     `json:"locked"`
	LoginName           string                                   `json:"loginName"`
	Parent              string                                   `json:"parent"`
	PasswordCredentials AdministratorsPasswordCredentialAPIModel `json:"passwordCredentials"`
	RoleName            string                                   `json:"roleName"`
}

type AdministratorsPasswordCredentialAPIModel struct {
	Password        string `json:"password"`
	PasswordExpired bool   `json:"passwordExpired"`
}

type AdministratorsRightsAPIModel struct {
	CanReadOnly                          bool `json:"canReadOnly"`
	IsMaker                              bool `json:"isMaker"`
	IsChecker                            bool `json:"isChecker"`
	CanCreateUsers                       bool `json:"canCreateUsers"`
	CanUpdateUsers                       bool `json:"canUpdateUsers"`
	CanAccessHelpDesk                    bool `json:"canAccessHelpDesk"`
	CanSeeFullAuditLog                   bool `json:"canSeeFullAuditLog"`
	CanManageAdministrators              bool `json:"canManageAdministrators"`
	CanManageApplications                bool `json:"canManageApplications"`
	CanManageSharedFolders               bool `json:"canManageSharedFolders"`
	CanManageBusinessUnits               bool `json:"canManageBusinessUnits"`
	CanManageRouteTemplates              bool `json:"canManageRouteTemplates"`
	CanManageExternalScriptStep          bool `json:"canManageExternalScriptStep"`
	CanManageExternalScriptRootExecution bool `json:"canManageExternalScriptRootExecution"`
	CanManageLoginRestrictionPolicies    bool `json:"canManageLoginRestrictionPolicies"`
	CanManageIcapSettings                bool `json:"canManageIcapSettings"`
}
