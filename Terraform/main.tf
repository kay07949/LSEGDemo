provider "aws" {
   region = "eu-west-2"
}

resource "aws_lambda_function" "lseglambda" {
   function_name = var.lambdafunction

   # The bucket name as created earlier with "aws s3api create-bucket"
   s3_bucket = var.s3bucket
   s3_key    = "pythonscript.zip"
   handler = "pythonscript.lambda_handler"
   runtime = "python3.8"

   role = aws_iam_role.lambda_exec.arn

}

resource "aws_iam_role" "lambda_exec" {
   name = "lseg_example_lambda"

   assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

}

resource "aws_lambda_permission" "apigw" {
   statement_id  = "AllowAPIGatewayInvoke"
   action        = "lambda:InvokeFunction"
   function_name = aws_lambda_function.lseglambda.function_name
   principal     = "apigateway.amazonaws.com"

   # The "/*/*" portion grants access from any method on any resource
   # within the API Gateway REST API.
   source_arn = "${aws_api_gateway_rest_api.lsegrestapi.execution_arn}/*/*"
}