resource "axwayst_administrators" "example-master" {
  id        = "example-admin"
  role_name = "Master Administrator"
  password_credentials = {
    password = "test1234"
  }
}
