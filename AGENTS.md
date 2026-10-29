
# UTOP14 — Project Agent Instructions

## Project Overview
UTOP14 is a full-stack streetwear e-commerce
application developed for Well Architected SOC 14.

## Primary Stack
- Python
- Flask
- Jinja2
- HTML5, CSS3, JavaScript
- PostgreSQL
- Flask-SQLAlchemy
- Flask-Migrate
- Flask-Login
- Flask-WTF
- Gunicorn
- Nginx
- pytest
- Ruff

## Architecture
- Use Flask application factory pattern.
- Use Blueprints for modular routing.
- Separate routes, models, services and templates.
- Use SQLAlchemy for database operations.
- Use Flask-Migrate for schema migrations.
- Keep development and production configurations separate.
- Use environment variables for configuration.

## Business Requirements
- Streetwear products and categories.
- Product sizes and colors.
- Individual stock per product variant.
- Customer registration and authentication.
- Shopping cart and checkout.
- Order history.
- Admin product and inventory management.

## Design Requirements
- Dark premium streetwear aesthetic.
- Responsive desktop and mobile layouts.
- Consistent typography and spacing.
- Reusable Jinja2 components.
- Accessible semantic HTML.
- Avoid unnecessary frontend frameworks.

## Security Requirements
- Hash passwords securely.
- Enforce server-side role authorization.
- Enable CSRF protection.
- Validate all user input.
- Use parameterized database operations.
- Never commit secrets or .env files.
- Never expose database credentials.
- Do not log passwords, tokens or secrets.
- Protect administrative operations.
- Use database transactions for order processing.

## Coding Standards
- Follow PEP 8.
- Use type hints where appropriate.
- Avoid duplicated business logic.
- Use Decimal for monetary calculations.
- Keep code modular and maintainable.
- Document important design decisions.

## Testing
- Write tests for major features.
- Test authentication and authorization.
- Test product and inventory behavior.
- Test cart and order processing.
- Run relevant tests after changes.
- Report actual test results.

## Agent Workflow
1. Inspect existing project files.
2. Understand the existing architecture.
3. Present an implementation plan.
4. Implement only the approved milestone.
5. Run tests and linting.
6. Summarize modified files.
7. Report unresolved issues.
8. Wait for approval before the next milestone.

## Restrictions
- Do not delete user data without approval.
- Do not run destructive database operations
  without explicit approval.
- Do not modify production infrastructure
  without explicit approval.
- Do not disable security controls to bypass errors.
- Never invent successful test results.
- Do not expose secrets in terminal output.
