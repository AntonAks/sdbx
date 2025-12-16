.PHONY: help bootstrap deploy-dev deploy-prod destroy-dev destroy-prod destroy-all plan-dev plan-prod init-dev init-prod clean status

# Default target
help: ## Show this help message
	@echo "sdbx - Zero-Knowledge File Sharing"
	@echo ""
	@echo "Available commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36mmake %-15s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Quick start:"
	@echo "  1. make bootstrap    (one-time setup)"
	@echo "  2. make deploy-dev   (deploy to dev)"
	@echo ""

bootstrap: ## Bootstrap Terraform backend (run once)
	@./scripts/bootstrap-terraform-backend.sh

deploy-dev: ## Deploy dev environment
	@./scripts/deploy-dev.sh

deploy-prod: ## Deploy prod environment
	@echo "🚀 Deploying to PRODUCTION..."
	@ACCOUNT_ID=$$(aws sts get-caller-identity --query Account --output text) && \
		BACKEND_BUCKET="sdbx-terraform-state-$$ACCOUNT_ID" && \
		cd terraform/environments/prod && \
		cp -n terraform.tfvars.example terraform.tfvars 2>/dev/null || true && \
		terraform init -backend-config="bucket=$$BACKEND_BUCKET" && \
		terraform plan -out=tfplan && \
		echo "" && \
		read -p "Apply to PRODUCTION? (yes/no): " confirm && \
		if [ "$$confirm" = "yes" ]; then \
			terraform apply tfplan && rm -f tfplan; \
		else \
			echo "❌ Aborted" && rm -f tfplan; \
		fi

destroy-dev: ## Destroy dev environment
	@./scripts/destroy-dev.sh

destroy-prod: ## Destroy prod environment
	@./scripts/destroy-prod.sh

destroy-all: ## Destroy all infrastructure
	@./scripts/destroy-all.sh

plan-dev: ## Show Terraform plan for dev
	@cd terraform/environments/dev && \
		terraform plan

plan-prod: ## Show Terraform plan for prod
	@cd terraform/environments/prod && \
		terraform plan

init-dev: ## Initialize Terraform for dev
	@ACCOUNT_ID=$$(aws sts get-caller-identity --query Account --output text) && \
		BACKEND_BUCKET="sdbx-terraform-state-$$ACCOUNT_ID" && \
		cd terraform/environments/dev && \
		cp -n terraform.tfvars.example terraform.tfvars 2>/dev/null || true && \
		terraform init -backend-config="bucket=$$BACKEND_BUCKET"

init-prod: ## Initialize Terraform for prod
	@ACCOUNT_ID=$$(aws sts get-caller-identity --query Account --output text) && \
		BACKEND_BUCKET="sdbx-terraform-state-$$ACCOUNT_ID" && \
		cd terraform/environments/prod && \
		cp -n terraform.tfvars.example terraform.tfvars 2>/dev/null || true && \
		terraform init -backend-config="bucket=$$BACKEND_BUCKET"

output-dev: ## Show dev environment outputs
	@cd terraform/environments/dev && \
		terraform output

output-prod: ## Show prod environment outputs
	@cd terraform/environments/prod && \
		terraform output

status: ## Show deployment status
	@echo "📊 sdbx Deployment Status"
	@echo ""
	@echo "AWS Account:"
	@aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || echo "  ⚠️  Not configured"
	@echo ""
	@echo "Terraform Backend:"
	@aws s3 ls sdbx-terraform-state 2>/dev/null && echo "  ✓ Backend exists" || echo "  ✗ Backend not created (run: make bootstrap)"
	@echo ""
	@echo "Dev Environment:"
	@if [ -f terraform/environments/dev/.terraform/terraform.tfstate ]; then \
		echo "  ✓ Initialized"; \
		cd terraform/environments/dev && terraform workspace show 2>/dev/null || true; \
	else \
		echo "  ✗ Not initialized (run: make init-dev)"; \
	fi
	@echo ""
	@echo "Prod Environment:"
	@if [ -f terraform/environments/prod/.terraform/terraform.tfstate ]; then \
		echo "  ✓ Initialized"; \
		cd terraform/environments/prod && terraform workspace show 2>/dev/null || true; \
	else \
		echo "  ✗ Not initialized (run: make init-prod)"; \
	fi

validate-dev: ## Validate dev Terraform configuration
	@cd terraform/environments/dev && \
		terraform validate

validate-prod: ## Validate prod Terraform configuration
	@cd terraform/environments/prod && \
		terraform validate

format: ## Format all Terraform files
	@terraform fmt -recursive terraform/

clean: ## Clean local Terraform files
	@echo "🧹 Cleaning local Terraform files..."
	@find terraform -type d -name ".terraform" -exec rm -rf {} + 2>/dev/null || true
	@find terraform -type f -name "*.tfplan" -delete 2>/dev/null || true
	@find terraform -type f -name "*.tfstate.backup" -delete 2>/dev/null || true
	@find terraform/modules/api/modules/lambda/builds -type f -name "*.zip" -delete 2>/dev/null || true
	@echo "  ✓ Cleaned"

test-backend: ## Test backend Python code
	@cd backend && \
		pip install -q -r requirements.txt && \
		pytest tests/ -v

lint-backend: ## Lint backend Python code
	@cd backend && \
		black --check lambdas/ shared/ && \
		isort --check lambdas/ shared/

format-backend: ## Format backend Python code
	@cd backend && \
		black lambdas/ shared/ && \
		isort lambdas/ shared/

install-backend: ## Install backend dependencies
	@cd backend && \
		pip install -r requirements.txt

deploy-frontend-dev: ## Deploy frontend to dev S3
	@BUCKET=$$(cd terraform/environments/dev && terraform output -raw static_bucket_name) && \
		aws s3 sync frontend/ s3://$$BUCKET/ --delete && \
		DIST_ID=$$(cd terraform/environments/dev && terraform output -raw cloudfront_distribution_id) && \
		aws cloudfront create-invalidation --distribution-id $$DIST_ID --paths "/*"

deploy-frontend-prod: ## Deploy frontend to prod S3
	@BUCKET=$$(cd terraform/environments/prod && terraform output -raw static_bucket_name) && \
		aws s3 sync frontend/ s3://$$BUCKET/ --delete && \
		DIST_ID=$$(cd terraform/environments/prod && terraform output -raw cloudfront_distribution_id) && \
		aws cloudfront create-invalidation --distribution-id $$DIST_ID --paths "/*"

logs-dev: ## Show recent Lambda logs from dev
	@FUNCTIONS=$$(cd terraform/environments/dev && terraform output -json lambda_function_arns | jq -r 'keys[]') && \
		for func in $$FUNCTIONS; do \
			echo "📋 Logs for sdbx-dev-$$func:"; \
			aws logs tail /aws/lambda/sdbx-dev-$$func --since 1h --follow=false 2>/dev/null | head -20 || echo "  No logs"; \
			echo ""; \
		done

costs: ## Estimate monthly costs
	@echo "💰 Estimated Monthly Costs"
	@echo ""
	@echo "Dev Environment:  ~\$$5-10/month"
	@echo "Prod Environment: ~\$$20-100/month (traffic dependent)"
	@echo ""
	@echo "For exact costs, check AWS Cost Explorer:"
	@echo "https://console.aws.amazon.com/cost-management/home"
