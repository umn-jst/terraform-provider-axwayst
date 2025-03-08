terraform {
  required_providers {
    axwayst = {
      source = "umn-jst/awx"
    }
  }
}

# This block below can be omitted if you set these three enviornment variables:
#  - AXWAYST_HOST
#  - AXWAYST_USERNAME
#  - AXWAYST_PASSWORD
provider "awx" {
  endpoint = "https://axway.example.com:8444"
  username = "admin"
  password = "password"
}

