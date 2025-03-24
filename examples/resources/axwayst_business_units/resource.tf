resource "axwayst_business_units" "simple_business_unit" {
  name        = "simple-example"
  base_folder = "/awxay_home/simple-example"
}

resource "axwayst_business_units" "example-parent-bu" {
  name        = "example-parent-bu"
  base_folder = "/awxay_home/example-parent-bu"
}

resource "axwayst_business_units" "example-complex" {
  name                                 = "example-complex-bu"
  parent                               = axwayst_business_units.example-parent-bu.name
  business_unit_hierarchy              = "${axwayst_business_units.example-parent-bu.name}/example-complex-bu"
  base_folder                          = "/axway_home/example-parent-bu/example-complex-bu"
  base_folder_modifying_allowed        = true
  home_folder_modifying_allowed        = true
  dmz                                  = "DMZ"
  shared_folders_collaboration_allowed = true

  html_template_settings = {
    html_template_folder_path = "ST Web Client"
    is_allowed_for_modifying  = true
  }

  transfers_api_settings = {
    transfers_web_service_allowed           = true
    is_web_service_rights_modifying_allowed = false
  }

  adhoc_settings = {
    auth_by_email                     = true
    auth_by_email_modifying_allowed   = true
    delivery_method_modifying_allowed = true
    delivery_method                   = "DISABLED"
    enrollment_template               = "default"
    notification_template             = "exampleNotificationFile.xhtml"
  }

  enabled_icap_servers = ["exampe-icap"]

  additional_attributes = {
    "userVars.example_addt_atrbt2"  = "201",
    "userVars.example_addtl_atrbt1" = "example-value1"
  }

  file_archiving_settings = {
    policy                        = "default"
    policy_modifying_allowed      = false
    folder_policy                 = "default"
    encryption_certificate_policy = "default"
    custom_file_size_policy       = "default"
    custom_file_size              = 0
  }
  login_restriction_settings = {
    is_policy_modifying_allowed = true
  }

  bandwidth_limits = {
    policy                = "custom"
    modify_limits_allowed = true
    inbound_limit         = 50
    outbound_limit        = 50
  }
}
