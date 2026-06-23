import type { Command } from 'commander';
import { ComplianceMapper } from '../../compliance/ComplianceMapper.js';
import { scan, getExitCode } from '../../scanner/Scanner.js';
import { loadConfig } from '../../utils/config.js';
import type { ComplianceAssessment } from '../../compliance/ComplianceMapper.js';

type ComplianceFramework = 'soc2' | 'iso27001' | 'gdpr';

function formatAssessmentText(assessment: ComplianceAssessment): string {
  const lines: string[] = [
    '',
    `${assessment.framework} Compliance Assessment`,
    '━'.repeat(60),
    `Overall score: ${assessment.overallScore}/100`,
    `Assessment date: ${assessment.assessmentDate.toISOString()}`,
    '',
    'Controls:',
  ];

  for (const control of assessment.controlAssessments) {
    const statusIcon = control.status === 'compliant' ? '✅'
      : control.status === 'partially_compliant' ? '⚠️'
        : '❌';
    lines.push(
      `${statusIcon} ${control.controlId} — ${control.controlName} (${control.score}/100, ${control.status})`
    );
    if (control.recommendations.length > 0) {
      for (const rec of control.recommendations) {
        lines.push(`     • ${rec}`);
      }
    }
  }

  if (assessment.nonCompliantControls.length > 0) {
    lines.push('');
    lines.push(`Non-compliant controls: ${assessment.nonCompliantControls.join(', ')}`);
  }

  if (assessment.recommendations.length > 0) {
    lines.push('');
    lines.push('Recommendations:');
    for (const rec of assessment.recommendations) {
      lines.push(`  • ${rec}`);
    }
  }

  return lines.join('\n');
}

async function runAssessment(
  framework: ComplianceFramework,
  path: string | undefined,
  format: 'text' | 'json'
): Promise<number> {
  const config = loadConfig(path !== undefined ? { path } : {});
  if (config.paths.length === 0) {
    console.error('No AI CLI configuration directories found.');
    return 1;
  }

  const scanResult = await scan(config);
  const mapper = new ComplianceMapper();

  const assessment = framework === 'iso27001'
    ? await mapper.assessISO27001(scanResult)
    : framework === 'gdpr'
      ? await mapper.assessGDPR(scanResult)
      : await mapper.assessSOC2(scanResult);

  if (format === 'json') {
    console.log(JSON.stringify(assessment, null, 2));
  } else {
    console.log(formatAssessmentText(assessment));
  }

  const scanExit = getExitCode(scanResult, config);
  const complianceFailed = assessment.nonCompliantControls.length > 0 || assessment.overallScore < 80;
  return complianceFailed || scanExit !== 0 ? 1 : 0;
}

export function registerComplianceCommand(program: Command): void {
  const complianceCmd = program
    .command('compliance')
    .description('Assess scan results against compliance frameworks (SOC2, ISO 27001, GDPR)');

  complianceCmd
    .command('assess')
    .description('Scan and assess compliance posture')
    .argument('[path]', 'Path to scan (defaults to AI CLI config directories)')
    .option('-f, --framework <name>', 'Framework: soc2, iso27001, gdpr', 'soc2')
    .option('--format <format>', 'Output format: text or json', 'text')
    .action(async (path: string | undefined, options: { framework: string; format: string }) => {
      try {
        const framework = options.framework.toLowerCase() as ComplianceFramework;
        if (!['soc2', 'iso27001', 'gdpr'].includes(framework)) {
          console.error(`Unknown framework: ${options.framework}. Use soc2, iso27001, or gdpr.`);
          process.exit(1);
        }

        const format = options.format === 'json' ? 'json' : 'text';
        const exitCode = await runAssessment(framework, path, format);
        process.exit(exitCode);
      } catch (error) {
        console.error('Error assessing compliance:', error instanceof Error ? error.message : String(error));
        process.exit(3);
      }
    });
}
