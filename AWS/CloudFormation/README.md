# AWS CloudFormation Templates

This directory contains reusable AWS CloudFormation templates for common infrastructure deployments.

## 📁 Templates

### 1. VPC Template (`vpc-basic.yaml`)
A comprehensive VPC setup with public and private subnets, internet gateway, and NAT gateway.

**Features:**
- VPC with configurable CIDR block
- 2 public subnets (for load balancers, bastion hosts)
- 2 private subnets (for application servers, databases)
- Internet Gateway for public internet access
- NAT Gateway for private subnet internet access
- Proper route table configurations
- Environment-based naming and tagging

**Usage:**
```bash
aws cloudformation deploy \
  --template-file vpc-basic.yaml \
  --stack-name my-vpc-stack \
  --parameter-overrides Environment=prod
```

**Parameters:**
- `VpcCidr`: VPC CIDR block (default: 10.0.0.0/16)
- `Environment`: Environment name (dev/staging/prod)
- `PublicSubnet1Cidr`: First public subnet CIDR
- `PublicSubnet2Cidr`: Second public subnet CIDR
- `PrivateSubnet1Cidr`: First private subnet CIDR
- `PrivateSubnet2Cidr`: Second private subnet CIDR

### 2. EC2 Instance Template (`ec2-instance.yaml`)
Complete EC2 instance deployment with security groups, IAM roles, and monitoring.

**Features:**
- EC2 instance with configurable instance type
- Security group with SSH, HTTP, and HTTPS access
- IAM role with CloudWatch and SSM permissions
- CloudWatch alarms for CPU monitoring
- SNS topic for alarm notifications
- User data script for basic web server setup

**Usage:**
```bash
aws cloudformation deploy \
  --template-file ec2-instance.yaml \
  --stack-name my-ec2-stack \
  --parameter-overrides \
    InstanceType=t3.micro \
    KeyPairName=my-key-pair \
    VpcId=vpc-12345678 \
    SubnetId=subnet-12345678 \
    Environment=dev
```

**Parameters:**
- `InstanceType`: EC2 instance type (t3.micro, t3.small, etc.)
- `KeyPairName`: Existing EC2 key pair for SSH access
- `VpcId`: VPC ID where instance will be launched
- `SubnetId`: Subnet ID where instance will be launched
- `Environment`: Environment name
- `InstanceName`: Name for the EC2 instance

### 3. S3 Bucket Template (`s3-bucket.yaml`)
Secure S3 bucket with encryption, lifecycle policies, and access controls.

**Features:**
- S3 bucket with server-side encryption
- Versioning enabled by default
- Lifecycle policies for cost optimization
- Public access blocking
- Bucket policy for encryption enforcement
- CloudWatch alarms for bucket size monitoring
- IAM user with S3 access permissions

**Usage:**
```bash
aws cloudformation deploy \
  --template-file s3-bucket.yaml \
  --stack-name my-s3-stack \
  --parameter-overrides \
    BucketName=my-unique-bucket-name \
    Environment=prod
```

**Parameters:**
- `BucketName`: Globally unique bucket name
- `Environment`: Environment name
- `VersioningEnabled`: Enable versioning (true/false)
- `PublicAccessBlock`: Block public access (true/false)
- `LifecycleEnabled`: Enable lifecycle policies (true/false)

## 🔧 Best Practices

### Security
- Always use IAM roles instead of access keys when possible
- Implement least privilege access
- Enable encryption for all data at rest
- Use security groups to restrict network access
- Enable CloudTrail for audit logging

### Cost Optimization
- Use appropriate instance types for workloads
- Implement S3 lifecycle policies
- Monitor costs with CloudWatch alarms
- Use Spot instances for non-critical workloads
- Right-size resources based on actual usage

### Monitoring
- Set up CloudWatch alarms for critical metrics
- Use SNS topics for alerting
- Implement proper logging
- Monitor costs and resource utilization

## 📊 Outputs

Each template provides useful outputs that can be referenced by other stacks:

### VPC Template Outputs
- `VpcId`: VPC identifier
- `PublicSubnets`: Comma-separated list of public subnet IDs
- `PrivateSubnets`: Comma-separated list of private subnet IDs
- Individual subnet IDs for specific references

### EC2 Template Outputs
- `InstanceId`: EC2 instance identifier
- `PublicIP`: Public IP address
- `SecurityGroupId`: Security group identifier
- `IAMRoleArn`: IAM role ARN

### S3 Template Outputs
- `BucketName`: S3 bucket name
- `BucketArn`: S3 bucket ARN
- `S3UserAccessKeyId`: Access key for S3 user
- `S3UserSecretAccessKey`: Secret access key for S3 user

## 🚀 Deployment Examples

### Complete Environment Setup
```bash
# 1. Deploy VPC
aws cloudformation deploy \
  --template-file vpc-basic.yaml \
  --stack-name prod-vpc \
  --parameter-overrides Environment=prod

# 2. Deploy S3 bucket
aws cloudformation deploy \
  --template-file s3-bucket.yaml \
  --stack-name prod-s3 \
  --parameter-overrides \
    BucketName=my-prod-bucket-$(date +%s) \
    Environment=prod

# 3. Deploy EC2 instance
aws cloudformation deploy \
  --template-file ec2-instance.yaml \
  --stack-name prod-web-server \
  --parameter-overrides \
    InstanceType=t3.small \
    KeyPairName=prod-key \
    VpcId=$(aws cloudformation describe-stacks --stack-name prod-vpc --query 'Stacks[0].Outputs[?OutputKey==`VpcId`].OutputValue' --output text) \
    SubnetId=$(aws cloudformation describe-stacks --stack-name prod-vpc --query 'Stacks[0].Outputs[?OutputKey==`PublicSubnet1`].OutputValue' --output text) \
    Environment=prod
```

## 🔍 Validation

Validate templates before deployment:
```bash
aws cloudformation validate-template --template-body file://vpc-basic.yaml
```

## 📝 Notes

- All templates use environment-based naming for easy identification
- Templates include proper tagging for cost allocation
- Security groups follow the principle of least privilege
- All templates are designed to be idempotent
- Use CloudFormation drift detection to monitor changes

## 🛠️ Customization

To customize these templates for your specific needs:

1. **Modify Parameters**: Adjust default values and add new parameters
2. **Add Resources**: Include additional AWS resources as needed
3. **Update Security**: Modify security group rules and IAM policies
4. **Enhance Monitoring**: Add more CloudWatch alarms and metrics
5. **Cost Optimization**: Implement additional cost-saving measures

## 📚 Additional Resources

- [AWS CloudFormation Documentation](https://docs.aws.amazon.com/cloudformation/)
- [AWS CloudFormation Best Practices](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/) 