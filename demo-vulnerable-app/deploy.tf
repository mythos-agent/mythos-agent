resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "my-app-data"
  acl    = "private"
}

resource "aws_db_instance" "main" {
  engine   = "postgres"
  password = "SuperSecret123!"
}
