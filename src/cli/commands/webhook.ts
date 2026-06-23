import type { Command } from 'commander';
import { sendWebhook, detectWebhookType } from '../../features/webhooks.js';
import type { ScanResult } from '../../types.js';
import type { WebhookConfig } from '../../features/webhooks.js';
import { errorMessage } from '../helpers.js';

export function registerWebhookCommand(program: Command): void {
  program
    .command('webhook')
    .description('Test webhook notifications')
    .argument('<url>', 'Webhook URL to test')
    .option('--type <type>', 'Webhook type: slack, discord, teams, generic')
    .option('--test', 'Send a test notification')
    .action(async (url: string, options: { type?: string; test?: boolean }) => {
      try {
        const type = (options.type ?? detectWebhookType(url)) as WebhookConfig['type'];
        console.log(`Detected webhook type: ${type}`);

        if (options.test) {
          const mockResult: ScanResult = {
            success: true,
            findings: [],
            summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            analyzedFiles: 10,
            duration: 1234,
            endTime: new Date(),
            startTime: new Date(),
            scannedPaths: [],
            totalFiles: 10,
            skippedFiles: 0,
            findingsBySeverity: { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [] },
            findingsByCategory: {} as ScanResult['findingsByCategory'],
            overallRiskScore: 0,
            errors: [],
          };

          console.log('Sending test notification...');
          const result = await sendWebhook(mockResult, {
            url,
            type,
            includeDetails: true,
          });

          if (result.success) {
            console.log(`✅ Webhook test successful (status: ${result.statusCode})`);
          } else {
            console.error(`❌ Webhook test failed: ${result.error}`);
            process.exit(1);
          }
        }
      } catch (error) {
        console.error('Error testing webhook:', errorMessage(error));
        process.exit(1);
      }
    });
}
