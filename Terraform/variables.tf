variable "s3bucket" {
    type = string
    description = "s3bucketname"
    default = "lseginterview"
   
}

variable "lambdafunction" {
    type = string
    description = "lambda function Name"
    default = "LSEGDemo"
}