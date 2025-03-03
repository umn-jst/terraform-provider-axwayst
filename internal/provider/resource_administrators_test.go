package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

func TestAccAdministrator(t *testing.T) {
	loginname := "test-user-" + acctest.RandString(5)
	resource1 := AdministratorsAPIModel{
		LoginName: loginname,
		RoleName:  "Master Administrator",
		PasswordCredentials: AdministratorsPasswordCredentialAPIModel{
			Password: fmt.Sprintf("!%v%v!", acctest.RandString(10), acctest.RandInt()),
		},
	}
	resource2 := AdministratorsAPIModel{
		LoginName:           loginname,
		RoleName:            "Master Administrator",
		LocalAuthentication: false,
	}
	resource3 := AdministratorsAPIModel{
		LoginName:           "test-user-" + acctest.RandString(5),
		RoleName:            "Delegated Administrator",
		LocalAuthentication: false,
		Parent:              "admin",
		FullCreationPath:    "admin",
		IsLimited:           true,
		AdministratorRights: AdministratorsRightsAPIModel{
			CanReadOnly:                          true,
			IsMaker:                              false,
			IsChecker:                            false,
			CanCreateUsers:                       false,
			CanUpdateUsers:                       false,
			CanAccessHelpDesk:                    false,
			CanSeeFullAuditLog:                   false,
			CanManageAdministrators:              false,
			CanManageApplications:                false,
			CanManageSharedFolders:               false,
			CanManageBusinessUnits:               false,
			CanManageRouteTemplates:              false,
			CanManageExternalScriptStep:          false,
			CanManageExternalScriptRootExecution: false,
			CanManageLoginRestrictionPolicies:    false,
			CanManageIcapSettings:                false,
		},
	}
	resource.Test(t, resource.TestCase{
		PreCheck: func() { testAccPreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_1_0), // built-in check from tfversion package
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserResource1Config(resource1),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("id"),
						knownvalue.StringExact(resource1.LoginName),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("role_name"),
						knownvalue.StringExact(resource1.RoleName),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("is_limited"),
						knownvalue.Bool(false),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("local_authentication"),
						knownvalue.Bool(true),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("dual_authentication"),
						knownvalue.Bool(false),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("locked"),
						knownvalue.Bool(false),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("password_credentials"),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"password":         knownvalue.StringExact(resource1.PasswordCredentials.Password),
							"password_expired": knownvalue.Bool(false),
						}),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("administrator_rights"),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"can_read_only":                             knownvalue.Bool(false),
							"is_maker":                                  knownvalue.Bool(true),
							"is_checker":                                knownvalue.Bool(true),
							"can_create_users":                          knownvalue.Bool(true),
							"can_update_users":                          knownvalue.Bool(true),
							"can_access_help_desk":                      knownvalue.Bool(true),
							"can_see_full_audit_log":                    knownvalue.Bool(true),
							"can_manage_administrators":                 knownvalue.Bool(true),
							"can_manage_applications":                   knownvalue.Bool(true),
							"can_manage_shared_folders":                 knownvalue.Bool(true),
							"can_manage_business_units":                 knownvalue.Bool(true),
							"can_manage_route_templates":                knownvalue.Bool(true),
							"can_manage_external_script_step":           knownvalue.Bool(true),
							"can_manage_external_script_root_execution": knownvalue.Bool(true),
							"can_manage_login_restriction_policies":     knownvalue.Bool(true),
							"can_manage_icap_settings":                  knownvalue.Bool(true),
						}),
					),
				},
			},
			// ImportState testing
			{
				ResourceName:            "axwayst_administrators.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password"},
			},
			// Update and Read testing
			{
				Config: testAccUserResource2Config(resource2),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("id"),
						knownvalue.StringExact(resource2.LoginName),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("role_name"),
						knownvalue.StringExact(resource2.RoleName),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("is_limited"),
						knownvalue.Bool(false),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("local_authentication"),
						knownvalue.Bool(resource2.LocalAuthentication),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("dual_authentication"),
						knownvalue.Bool(false),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("locked"),
						knownvalue.Bool(false),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("password_credentials"),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"password":         knownvalue.StringExact(""),
							"password_expired": knownvalue.Bool(false),
						}),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test",
						tfjsonpath.New("administrator_rights"),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"can_read_only":                             knownvalue.Bool(false),
							"is_maker":                                  knownvalue.Bool(true),
							"is_checker":                                knownvalue.Bool(true),
							"can_create_users":                          knownvalue.Bool(true),
							"can_update_users":                          knownvalue.Bool(true),
							"can_access_help_desk":                      knownvalue.Bool(true),
							"can_see_full_audit_log":                    knownvalue.Bool(true),
							"can_manage_administrators":                 knownvalue.Bool(true),
							"can_manage_applications":                   knownvalue.Bool(true),
							"can_manage_shared_folders":                 knownvalue.Bool(true),
							"can_manage_business_units":                 knownvalue.Bool(true),
							"can_manage_route_templates":                knownvalue.Bool(true),
							"can_manage_external_script_step":           knownvalue.Bool(true),
							"can_manage_external_script_root_execution": knownvalue.Bool(true),
							"can_manage_login_restriction_policies":     knownvalue.Bool(true),
							"can_manage_icap_settings":                  knownvalue.Bool(true),
						}),
					),
				},
			},
			{
				Config: testAccUserResource3Config(resource3),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test-limited",
						tfjsonpath.New("id"),
						knownvalue.StringExact(resource3.LoginName),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test-limited",
						tfjsonpath.New("role_name"),
						knownvalue.StringExact(resource3.RoleName),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test-limited",
						tfjsonpath.New("is_limited"),
						knownvalue.Bool(resource3.IsLimited),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test-limited",
						tfjsonpath.New("local_authentication"),
						knownvalue.Bool(resource3.LocalAuthentication),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test-limited",
						tfjsonpath.New("dual_authentication"),
						knownvalue.Bool(false),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test-limited",
						tfjsonpath.New("locked"),
						knownvalue.Bool(false),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test-limited",
						tfjsonpath.New("password_credentials"),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"password":         knownvalue.StringExact(""),
							"password_expired": knownvalue.Bool(false),
						}),
					),
					statecheck.ExpectKnownValue(
						"axwayst_administrators.test-limited",
						tfjsonpath.New("administrator_rights"),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"can_read_only":                             knownvalue.Bool(resource3.AdministratorRights.CanReadOnly),
							"is_maker":                                  knownvalue.Bool(resource3.AdministratorRights.IsMaker),
							"is_checker":                                knownvalue.Bool(resource3.AdministratorRights.IsChecker),
							"can_create_users":                          knownvalue.Bool(resource3.AdministratorRights.CanCreateUsers),
							"can_update_users":                          knownvalue.Bool(resource3.AdministratorRights.CanUpdateUsers),
							"can_access_help_desk":                      knownvalue.Bool(resource3.AdministratorRights.CanAccessHelpDesk),
							"can_see_full_audit_log":                    knownvalue.Bool(resource3.AdministratorRights.CanSeeFullAuditLog),
							"can_manage_administrators":                 knownvalue.Bool(resource3.AdministratorRights.CanManageAdministrators),
							"can_manage_applications":                   knownvalue.Bool(resource3.AdministratorRights.CanManageApplications),
							"can_manage_shared_folders":                 knownvalue.Bool(resource3.AdministratorRights.CanManageSharedFolders),
							"can_manage_business_units":                 knownvalue.Bool(resource3.AdministratorRights.CanManageBusinessUnits),
							"can_manage_route_templates":                knownvalue.Bool(resource3.AdministratorRights.CanManageRouteTemplates),
							"can_manage_external_script_step":           knownvalue.Bool(resource3.AdministratorRights.CanManageExternalScriptStep),
							"can_manage_external_script_root_execution": knownvalue.Bool(resource3.AdministratorRights.CanManageExternalScriptRootExecution),
							"can_manage_login_restriction_policies":     knownvalue.Bool(resource3.AdministratorRights.CanManageLoginRestrictionPolicies),
							"can_manage_icap_settings":                  knownvalue.Bool(resource3.AdministratorRights.CanManageIcapSettings),
						}),
					),
				},
			},
		},
	})
}

func testAccUserResource1Config(resource AdministratorsAPIModel) string {
	return fmt.Sprintf(`
resource "axwayst_administrators" "test" {
  id		= "%s"
  role_name	= "%s"
  password_credentials = {
  	password = "%s"
  }
}
  `, resource.LoginName, resource.RoleName, resource.PasswordCredentials.Password)
}

func testAccUserResource2Config(resource AdministratorsAPIModel) string {
	return fmt.Sprintf(`
resource "axwayst_administrators" "test" {
  id					= "%s"
  role_name				= "%s"
  local_authentication 	= "%v"
}
  `, resource.LoginName, resource.RoleName, resource.LocalAuthentication)
}

func testAccUserResource3Config(resource AdministratorsAPIModel) string {
	return fmt.Sprintf(`
resource "axwayst_administrators" "test-limited" {
  id					= "%s"
  role_name				= "%s"
  local_authentication 	= "%v"
  parent				= "%v"
  full_creation_path 	= "%v"
  is_limited 			= %v
  administrator_rights = {
	can_read_only = %v
	is_maker = %v
	is_checker = %v
	can_create_users = %v
	can_update_users = %v
	can_access_help_desk = %v
	can_see_full_audit_log = %v
	can_manage_administrators = %v
	can_manage_applications = %v
	can_manage_shared_folders = %v
	can_manage_business_units = %v
	can_manage_route_templates = %v
	can_manage_external_script_step = %v
	can_manage_external_script_root_execution = %v
	can_manage_login_restriction_policies = %v
	can_manage_icap_settings = %v
  }
}
  `, resource.LoginName, resource.RoleName, resource.LocalAuthentication, resource.Parent, resource.FullCreationPath, resource.IsLimited,
		resource.AdministratorRights.CanReadOnly, resource.AdministratorRights.IsMaker, resource.AdministratorRights.IsChecker, resource.AdministratorRights.CanCreateUsers,
		resource.AdministratorRights.CanUpdateUsers, resource.AdministratorRights.CanAccessHelpDesk, resource.AdministratorRights.CanSeeFullAuditLog, resource.AdministratorRights.CanManageAdministrators,
		resource.AdministratorRights.CanManageApplications, resource.AdministratorRights.CanManageSharedFolders, resource.AdministratorRights.CanManageBusinessUnits,
		resource.AdministratorRights.CanManageRouteTemplates, resource.AdministratorRights.CanManageExternalScriptStep, resource.AdministratorRights.CanManageExternalScriptRootExecution,
		resource.AdministratorRights.CanManageLoginRestrictionPolicies, resource.AdministratorRights.CanManageIcapSettings)
}
