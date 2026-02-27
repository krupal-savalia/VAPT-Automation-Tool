# GitHub Actions Workflow Example

This repository includes GitHub Actions integration for automated security scanning.

## Setup

### 1. Add Scan Secrets (Optional)

In your GitHub repository settings:
- Go to **Settings** → **Secrets and variables** → **Actions**
- Add any required secrets (e.g., target URLs, authentication tokens)

### 2. Create Workflow File

Create `.github/workflows/security-scan.yml`:

```yaml
name: CSEH Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    # Run daily at 2 AM UTC
    - cron: '0 2 * * *'

jobs:
  scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    
    - name: Run CSEH Scanner
      run: |
        python cli.py ${{ secrets.TARGET_URL }} \
          --depth 3 \
          --format both \
          --report-dir ./reports
    
    - name: Upload reports
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: security-reports
        path: reports/
    
    - name: Check policy violations
      run: |
        python -c "
        import json
        with open('reports/report.json') as f:
            report = json.load(f)
        critical = report['scan']['summary']['critical']
        if critical > 0:
            print(f'❌ Critical vulnerabilities found: {critical}')
            exit(1)
        else:
            print('✅ No critical vulnerabilities found')
        "
    
    - name: Comment on PR
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const report = JSON.parse(fs.readFileSync('reports/report.json'));
          const summary = report.scan.summary;
          
          const comment = \`## 🔒 Security Scan Results
          
          - Critical: **\${summary.critical}**
          - High: **\${summary.high}**
          - Medium: **\${summary.medium}**
          - Low: \${summary.low}
          - Info: \${summary.info}
          
          [View full report](https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }})
          \`;
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: comment
          });
```

## Policy Configuration

Create `.github/cseh-policy.json`:

```json
{
  "fail_on_critical": true,
  "fail_on_high": true,
  "max_medium": 10,
  "max_low": 50
}
```

## Output Formats

The scanner can generate output in multiple formats for CI/CD integration:

- **JSON**: Detailed technical report
- **SARIF**: Static Analysis Results Interchange Format
- **GitHub Annotations**: For inline PR comments

## Example Outputs

### SARIF Output

```bash
python cli.py https://example.com -o report.sarif
```

Uploads to GitHub Security tab for analysis.

### GitHub Annotations

```bash
python cli.py https://example.com -o annotations.json
```

Creates annotations for inline feedback.

## Integration with Other Platforms

### GitLab CI

```yaml
security_scan:
  stage: security
  script:
    - pip install -r requirements.txt
    - python cli.py $CI_COMMIT_REF_NAME --format both
  artifacts:
    reports:
      sast: reports/report.sarif
    paths:
      - reports/
```

### Jenkins

```groovy
pipeline {
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    pip install -r requirements.txt
                    python cli.py $TARGET_URL --format both
                '''
                archiveArtifacts 'reports/**'
            }
        }
        stage('Policy Check') {
            steps {
                sh 'python -m scanner.reporting.devsecops check-policy reports/policy.json'
            }
        }
    }
}
```

## Best Practices

1. **Run Scheduled Scans**: Schedule scans weekly/daily
2. **Gate on Critical**: Fail PR if critical vulnerabilities found
3. **Archive Reports**: Keep historical reports for trend analysis
4. **Notify Teams**: Integrate with Slack/Teams for alerts
5. **Continuous Improvement**: Track vulnerability trends over time
