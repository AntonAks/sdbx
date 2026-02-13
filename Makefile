.PHONY: help bootstrap deploy-dev deploy-prod destroy-dev destroy-prod destroy-all plan-dev plan-prod init-dev init-prod clean test test-backend test-frontend test-backend-cov install-frontend-deps build-frontend dev-frontend init-salt-dev init-salt-prod check-salt-dev check-salt-prod

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

build-lambdas-dev: ## Build Lambda deployment packages for dev
	@./scripts/build-lambdas.sh dev

build-lambdas-prod: ## Build Lambda deployment packages for prod
	@./scripts/build-lambdas.sh prod

install-frontend-deps: ## Install frontend dependencies (Tailwind CSS)
	@if [ ! -d "node_modules" ]; then \
		echo "📦 Installing frontend dependencies..."; \
		npm install; \
	else \
		echo "✓ Frontend dependencies already installed"; \
	fi

build-frontend: install-frontend-deps ## Build frontend CSS with Tailwind
	@echo "🎨 Building Tailwind CSS..."
	@npm run build:css
	@echo "  ✓ CSS built to frontend/css/output.css"

dev-frontend: install-frontend-deps ## Watch mode for frontend development
	@echo "👀 Watching frontend CSS changes..."
	@echo "Press Ctrl+C to stop"
	@npm run dev:css

deploy-dev-infra: build-lambdas-dev ## Deploy dev infrastructure only (without frontend)
	@./scripts/deploy-dev.sh

deploy-dev: build-lambdas-dev build-frontend ## Deploy dev environment (backend + frontend)
	@echo "🚀 Deploying to DEVELOPMENT..."
	@echo ""
	@ACCOUNT_ID=$$(aws sts get-caller-identity --query Account --output text) && \
		BACKEND_BUCKET="sdbx-terraform-state-$$ACCOUNT_ID" && \
		cd terraform/environments/dev && \
		cp -n terraform.tfvars.example terraform.tfvars 2>/dev/null || true && \
		terraform init -backend-config="bucket=$$BACKEND_BUCKET" && \
		terraform validate && \
		terraform plan -out=tfplan && \
		echo "" && \
		read -p "Apply to DEVELOPMENT? (yes/no): " confirm && \
		if [ "$$confirm" = "yes" ]; then \
			terraform apply tfplan && rm -f tfplan && \
			echo "" && \
			echo "📦 Deploying frontend..." && \
			cd ../../.. && \
			echo "🔧 Patching API paths for dev environment..." && \
			find frontend/js -name "*.js" -exec sed -i "s|'/prod'|'/dev'|g" {} \; && \
			find frontend/js -name "*.js" -exec sed -i "s|/prod/|/dev/|g" {} \; && \
			BUCKET=$$(cd terraform/environments/dev && terraform output -raw static_bucket_name) && \
			aws s3 sync frontend/ s3://$$BUCKET/ --delete --exclude "tests/*" && \
			DIST_ID=$$(cd terraform/environments/dev && terraform output -raw cloudfront_distribution_id) && \
			aws cloudfront create-invalidation --distribution-id $$DIST_ID --paths "/*" && \
			echo "🔧 Restoring API paths..." && \
			find frontend/js -name "*.js" -exec sed -i "s|'/dev'|'/prod'|g" {} \; && \
			find frontend/js -name "*.js" -exec sed -i "s|/dev/|/prod/|g" {} \; && \
			echo "" && \
			echo "✅ Deployment complete!" && \
			echo "" && \
			echo "📊 Outputs:" && \
			cd terraform/environments/dev && terraform output; \
		else \
			echo "❌ Aborted" && rm -f tfplan; \
		fi

deploy-prod: build-lambdas-prod build-frontend ## Deploy prod environment (backend + frontend)
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
			terraform apply tfplan && rm -f tfplan && \
			echo "" && \
			echo "📦 Deploying frontend..." && \
			cd ../../.. && \
			BUCKET=$$(cd terraform/environments/prod && terraform output -raw static_bucket_name) && \
			aws s3 sync frontend/ s3://$$BUCKET/ --delete --exclude "tests/*" && \
			DIST_ID=$$(cd terraform/environments/prod && terraform output -raw cloudfront_distribution_id) && \
			aws cloudfront create-invalidation --distribution-id $$DIST_ID --paths "/*" && \
			echo "✅ Deployment complete!"; \
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

test: test-backend test-frontend ## Run all tests (backend + frontend)

test-backend: ## Run backend Python tests
	@echo "🧪 Running backend tests..."
	@if [ ! -d "backend/venv" ]; then \
		echo "📦 Creating virtual environment..."; \
		cd backend && python3 -m venv venv; \
	fi
	@cd backend && \
		. venv/bin/activate && \
		pip install -q -r requirements-test.txt && \
		pytest tests/ -v --tb=short
	@echo ""

test-backend-cov: ## Run backend tests with coverage report
	@echo "🧪 Running backend tests with coverage..."
	@if [ ! -d "backend/venv" ]; then \
		echo "📦 Creating virtual environment..."; \
		cd backend && python3 -m venv venv; \
	fi
	@cd backend && \
		. venv/bin/activate && \
		pip install -q -r requirements-test.txt && \
		pytest tests/ -v --cov=shared --cov-report=term-missing --cov-report=html
	@echo ""
	@echo "📊 Coverage report: backend/htmlcov/index.html"
	@echo ""

test-frontend: ## Run frontend JavaScript tests
	@echo "🧪 Running frontend tests..."
	@cd frontend && \
		node --test tests/*.test.js
	@echo ""

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

deploy-frontend-dev: build-frontend ## Deploy frontend to dev S3
	@echo "📦 Deploying frontend to DEV..."
	@echo "🔧 Patching API paths for dev environment..."
	@find frontend/js -name "*.js" -exec sed -i "s|'/prod'|'/dev'|g" {} \;
	@find frontend/js -name "*.js" -exec sed -i "s|/prod/|/dev/|g" {} \;
	@BUCKET=$$(cd terraform/environments/dev && terraform output -raw static_bucket_name) && \
		aws s3 sync frontend/ s3://$$BUCKET/ --delete --exclude "tests/*" && \
		DIST_ID=$$(cd terraform/environments/dev && terraform output -raw cloudfront_distribution_id) && \
		aws cloudfront create-invalidation --distribution-id $$DIST_ID --paths "/*" && \
		echo "🔧 Restoring API paths..." && \
		find frontend/js -name "*.js" -exec sed -i "s|'/dev'|'/prod'|g" {} \; && \
		find frontend/js -name "*.js" -exec sed -i "s|/dev/|/prod/|g" {} \; && \
		echo "✅ Frontend deployed to dev"

deploy-frontend-prod: build-frontend ## Deploy frontend to prod S3
	@echo "📦 Deploying frontend to PROD..."
	@BUCKET=$$(cd terraform/environments/prod && terraform output -raw static_bucket_name) && \
		aws s3 sync frontend/ s3://$$BUCKET/ --delete --exclude "tests/*" && \
		DIST_ID=$$(cd terraform/environments/prod && terraform output -raw cloudfront_distribution_id) && \
		aws cloudfront create-invalidation --distribution-id $$DIST_ID --paths "/*" && \
		echo "✅ Frontend deployed to prod"

init-salt-dev: ## Initialize IP hash salt for dev environment
	@./scripts/init-ip-hash-salt.sh sdbx dev

init-salt-prod: ## Initialize IP hash salt for prod environment
	@./scripts/init-ip-hash-salt.sh sdbx prod

check-salt-dev: ## Check if IP hash salt exists in dev Parameter Store
	@aws ssm get-parameter --name "/sdbx/dev/ip-hash-salt" --query "Parameter.{Name:Name,Type:Type,LastModified:LastModifiedDate}" --output table 2>/dev/null || echo "Salt not found. Run: make init-salt-dev"

check-salt-prod: ## Check if IP hash salt exists in prod Parameter Store
	@aws ssm get-parameter --name "/sdbx/prod/ip-hash-salt" --query "Parameter.{Name:Name,Type:Type,LastModified:LastModifiedDate}" --output table 2>/dev/null || echo "Salt not found. Run: make init-salt-prod"
