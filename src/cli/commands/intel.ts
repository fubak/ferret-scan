import type { Command } from 'commander';
import {
  loadThreatDatabase,
  saveThreatDatabase,
  addIndicators,
  searchIndicators,
  needsUpdate,
  type IndicatorType,
} from '../../intelligence/ThreatFeed.js';
import { errorMessage } from '../helpers.js';

export function registerIntelCommand(program: Command): void {
  const intelCmd = program
    .command('intel')
    .description('Manage threat intelligence');

  intelCmd
    .command('status')
    .description('Show threat intelligence database status')
    .option('--intel-dir <dir>', 'Threat intelligence directory', '.ferret-intel')
    .action((options: { intelDir: string }) => {
      try {
        const db = loadThreatDatabase(options.intelDir);
        const updateNeeded = needsUpdate(db, 24);

        console.log('🛡️  Threat Intelligence Status');
        console.log('━'.repeat(60));
        console.log(`Database Version: ${db.version}`);
        console.log(`Last Updated: ${new Date(db.lastUpdated).toLocaleString()}`);
        console.log(`Total Indicators: ${db.stats.totalIndicators}`);
        console.log(`Update Needed: ${updateNeeded ? '⚠️  Yes' : '✅ No'}`);
        console.log('');

        console.log('By Type:');
        for (const [type, count] of Object.entries(db.stats.byType)) {
          if (count > 0) {
            console.log(`  ${type}: ${count}`);
          }
        }
        console.log('');

        console.log('By Category:');
        for (const [category, count] of Object.entries(db.stats.byCategory)) {
          console.log(`  ${category}: ${count}`);
        }
        console.log('');

        console.log('Sources:');
        for (const source of db.sources) {
          console.log(`  ${source.enabled ? '✅' : '❌'} ${source.name}: ${source.description}`);
        }
      } catch (error) {
        console.error('Error loading threat intelligence:', errorMessage(error));
        process.exit(1);
      }
    });

  intelCmd
    .command('search')
    .description('Search threat intelligence indicators')
    .argument('<query>', 'Search term')
    .option('--intel-dir <dir>', 'Threat intelligence directory', '.ferret-intel')
    .option('--limit <num>', 'Maximum results', '20')
    .action((query: string, options: { intelDir: string; limit: string }) => {
      try {
        const db = loadThreatDatabase(options.intelDir);
        const results = searchIndicators(db, query);
        const limit = parseInt(options.limit, 10);

        console.log(`🔍 Found ${results.length} indicators matching "${query}"`);
        console.log('━'.repeat(60));

        for (const indicator of results.slice(0, limit)) {
          console.log(`[${indicator.severity.toUpperCase()}] ${indicator.type}: ${indicator.value}`);
          console.log(`  ${indicator.description}`);
          console.log(`  Tags: ${indicator.tags.join(', ')}`);
          console.log(`  Confidence: ${indicator.confidence}%`);
          console.log('');
        }

        if (results.length > limit) {
          console.log(`... and ${results.length - limit} more results`);
        }
      } catch (error) {
        console.error('Error searching threat intelligence:', errorMessage(error));
        process.exit(1);
      }
    });

  intelCmd
    .command('add')
    .description('Add threat intelligence indicator')
    .option('--type <type>', 'Indicator type (domain, ip, hash, package, pattern)', 'pattern')
    .option('--value <value>', 'Indicator value', true)
    .option('--category <category>', 'Threat category', 'unknown')
    .option('--severity <severity>', 'Severity level', 'medium')
    .option('--description <desc>', 'Description', '')
    .option('--confidence <num>', 'Confidence level (0-100)', '75')
    .option('--tags <tags>', 'Comma-separated tags', '')
    .option('--intel-dir <dir>', 'Threat intelligence directory', '.ferret-intel')
    .action((options: {
      type: string;
      value: string | boolean;
      category: string;
      severity: string;
      description: string;
      confidence: string;
      tags: string;
      intelDir: string;
    }) => {
      try {
        if (!options.value || typeof options.value !== 'string') {
          console.error('Error: --value is required');
          process.exit(1);
        }

        const db = loadThreatDatabase(options.intelDir);

        const newIndicator = {
          value: options.value,
          type: options.type as IndicatorType,
          category: options.category,
          severity: options.severity as 'high' | 'medium' | 'low' | 'critical',
          description: options.description || `Custom ${options.type} indicator`,
          source: 'user-added',
          confidence: parseInt(options.confidence, 10),
          tags: options.tags ? options.tags.split(',').map(t => t.trim()) : [],
          metadata: { addedBy: 'ferret-cli' },
        };

        const updatedDb = addIndicators(db, [newIndicator]);
        saveThreatDatabase(updatedDb, options.intelDir);

        console.log('✅ Added threat intelligence indicator:');
        console.log(`   Type: ${newIndicator.type}`);
        console.log(`   Value: ${newIndicator.value}`);
        console.log(`   Severity: ${newIndicator.severity}`);
        console.log(`   Confidence: ${newIndicator.confidence}%`);
      } catch (error) {
        console.error('Error adding indicator:', errorMessage(error));
        process.exit(1);
      }
    });
}
