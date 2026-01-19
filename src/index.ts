import * as core from '@actions/core';
import * as github from '@actions/github';
import * as glob from '@actions/glob';
import * as fs from 'fs';
import * as path from 'path';

// PII Patterns (same as Tork SDK)
const PII_PATTERNS = [
  { name: 'email', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, severity: 'medium' },
  { name: 'phone', pattern: /(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g, severity: 'medium' },
  { name: 'ssn', pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, severity: 'critical' },
  { name: 'credit_card', pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, severity: 'critical' },
  { name: 'api_key', pattern: /(?:api[_-]?key|apikey|secret[_-]?key)[\s]*[=:]\s*['"]?[\w-]{20,}['"]?/gi, severity: 'critical' },
  { name: 'aws_key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'private_key', pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'jwt', pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g, severity: 'high' },
  { name: 'ip_address', pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, severity: 'low' },
  { name: 'date_of_birth', pattern: /\b(?:dob|date of birth|birthday)[\s:]+\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/gi, severity: 'medium' },
  { name: 'passport', pattern: /\b[A-Z]{1,2}\d{6,9}\b/g, severity: 'high' },
  { name: 'medicare', pattern: /\b\d{4}\s?\d{5}\s?\d{1}\b/g, severity: 'high' },
  { name: 'tfn', pattern: /\b\d{3}\s?\d{3}\s?\d{3}\b/g, severity: 'high' }, // Australian Tax File Number
  { name: 'abn', pattern: /\b\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b/g, severity: 'medium' }, // Australian Business Number
];

interface Violation {
  file: string;
  line: number;
  column: number;
  type: string;
  severity: string;
  message: string;
  snippet: string;
}

interface ScanResult {
  score: number;
  violations: Violation[];
  filesScanned: number;
  piiDetected: boolean;
}

async function scanFile(filePath: string): Promise<Violation[]> {
  const violations: Violation[] = [];

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];

      for (const piiPattern of PII_PATTERNS) {
        const matches = line.matchAll(piiPattern.pattern);

        for (const match of matches) {
          violations.push({
            file: filePath,
            line: lineNum + 1,
            column: (match.index || 0) + 1,
            type: piiPattern.name,
            severity: piiPattern.severity,
            message: `Potential ${piiPattern.name.replace('_', ' ')} detected`,
            snippet: line.substring(Math.max(0, (match.index || 0) - 20), (match.index || 0) + match[0].length + 20),
          });
        }
      }
    }
  } catch (error) {
    core.warning(`Could not scan file: ${filePath}`);
  }

  return violations;
}

async function run(): Promise<void> {
  try {
    // Get inputs
    const apiKey = core.getInput('api-key', { required: true });
    const scanPath = core.getInput('scan-path') || '.';
    const failOnViolation = core.getInput('fail-on-violation') === 'true';
    const severityThreshold = core.getInput('severity-threshold') || 'medium';
    const scanMode = core.getInput('scan-mode') || 'full';
    const outputFormat = core.getInput('output-format') || 'markdown';

    core.info('🛡️ Tork AI Governance Scan Starting...');
    core.info(`📁 Scan path: ${scanPath}`);
    core.info(`🎯 Severity threshold: ${severityThreshold}`);

    // Find files to scan
    const globber = await glob.create(`${scanPath}/**/*.{ts,tsx,js,jsx,py,java,go,rb,php,cs,yaml,yml,json,env,txt,md}`, {
      followSymbolicLinks: false,
    });

    const files = await globber.glob();

    // Filter out common directories
    const filesToScan = files.filter(f =>
      !f.includes('node_modules') &&
      !f.includes('.git') &&
      !f.includes('dist') &&
      !f.includes('build') &&
      !f.includes('.next') &&
      !f.includes('__pycache__')
    );

    core.info(`📝 Found ${filesToScan.length} files to scan`);

    // Scan all files
    const allViolations: Violation[] = [];

    for (const file of filesToScan) {
      const violations = await scanFile(file);
      allViolations.push(...violations);
    }

    // Calculate score
    const severityWeights: Record<string, number> = {
      critical: 25,
      high: 15,
      medium: 10,
      low: 5,
    };

    let deductions = 0;
    for (const v of allViolations) {
      deductions += severityWeights[v.severity] || 5;
    }

    const score = Math.max(0, 100 - deductions);
    const piiDetected = allViolations.length > 0;

    // Filter violations by severity threshold
    const severityOrder = ['low', 'medium', 'high', 'critical'];
    const thresholdIndex = severityOrder.indexOf(severityThreshold);
    const relevantViolations = allViolations.filter(v =>
      severityOrder.indexOf(v.severity) >= thresholdIndex
    );

    // Set outputs
    core.setOutput('score', score.toString());
    core.setOutput('violations-count', allViolations.length.toString());
    core.setOutput('pii-detected', piiDetected.toString());

    // Generate report
    core.info('');
    core.info('═══════════════════════════════════════════════════════');
    core.info('🛡️  TORK AI GOVERNANCE REPORT');
    core.info('═══════════════════════════════════════════════════════');
    core.info('');
    core.info(`📊 Governance Score: ${score}/100`);
    core.info(`📁 Files Scanned: ${filesToScan.length}`);
    core.info(`⚠️  Total Violations: ${allViolations.length}`);
    core.info(`🚨 Violations Above Threshold: ${relevantViolations.length}`);
    core.info('');

    if (allViolations.length > 0) {
      // Group by severity
      const bySeverity: Record<string, Violation[]> = {};
      for (const v of allViolations) {
        if (!bySeverity[v.severity]) bySeverity[v.severity] = [];
        bySeverity[v.severity].push(v);
      }

      core.info('📋 Violations by Severity:');
      for (const severity of ['critical', 'high', 'medium', 'low']) {
        const count = bySeverity[severity]?.length || 0;
        const emoji = severity === 'critical' ? '🔴' : severity === 'high' ? '🟠' : severity === 'medium' ? '🟡' : '🟢';
        core.info(`   ${emoji} ${severity.toUpperCase()}: ${count}`);
      }
      core.info('');

      // Show top violations
      core.info('📍 Top Violations:');
      const topViolations = allViolations.slice(0, 10);
      for (const v of topViolations) {
        core.warning(`${v.file}:${v.line} - ${v.message} [${v.severity.toUpperCase()}]`);
      }

      if (allViolations.length > 10) {
        core.info(`   ... and ${allViolations.length - 10} more`);
      }
    } else {
      core.info('✅ No PII or governance violations detected!');
    }

    core.info('');
    core.info('═══════════════════════════════════════════════════════');
    core.info('');

    // Write SARIF file if requested
    if (outputFormat === 'sarif') {
      const sarif = generateSarif(allViolations);
      const sarifPath = 'tork-results.sarif';
      fs.writeFileSync(sarifPath, JSON.stringify(sarif, null, 2));
      core.setOutput('sarif-file', sarifPath);
      core.info(`📄 SARIF report written to: ${sarifPath}`);
    }

    // Write JSON report
    const reportPath = 'tork-report.json';
    const report = {
      timestamp: new Date().toISOString(),
      score,
      filesScanned: filesToScan.length,
      violations: allViolations,
      summary: {
        critical: allViolations.filter(v => v.severity === 'critical').length,
        high: allViolations.filter(v => v.severity === 'high').length,
        medium: allViolations.filter(v => v.severity === 'medium').length,
        low: allViolations.filter(v => v.severity === 'low').length,
      },
    };
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    core.info(`📄 Full report written to: ${reportPath}`);

    // Fail if violations exceed threshold
    if (failOnViolation && relevantViolations.length > 0) {
      core.setFailed(`❌ Found ${relevantViolations.length} governance violations at or above ${severityThreshold} severity. Score: ${score}/100`);
    } else if (piiDetected) {
      core.warning(`⚠️ PII detected but below severity threshold. Score: ${score}/100`);
    } else {
      core.info(`✅ Governance check passed! Score: ${score}/100`);
    }

  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(`Action failed: ${error.message}`);
    } else {
      core.setFailed('Action failed with unknown error');
    }
  }
}

function generateSarif(violations: Violation[]): object {
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Tork AI Governance',
            version: '1.0.0',
            informationUri: 'https://tork.network',
            rules: PII_PATTERNS.map(p => ({
              id: p.name,
              name: p.name.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase()),
              shortDescription: { text: `Detects ${p.name.replace('_', ' ')}` },
              defaultConfiguration: { level: p.severity === 'critical' ? 'error' : p.severity === 'high' ? 'warning' : 'note' },
            })),
          },
        },
        results: violations.map(v => ({
          ruleId: v.type,
          level: v.severity === 'critical' ? 'error' : v.severity === 'high' ? 'warning' : 'note',
          message: { text: v.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: v.file },
                region: { startLine: v.line, startColumn: v.column },
              },
            },
          ],
        })),
      },
    ],
  };
}

run();
