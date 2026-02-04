import * as p from '@clack/prompts';
import chalk from 'chalk';
import { existsSync, writeFileSync } from 'fs';
import { join } from 'path';
import { loadConfig } from '../../core/config.js';
import { getExecutor } from '../../providers/executors/index.js';
import { CoreScanner } from '../../core/scanner.js';
import { scanCodebase } from '../../core/scanner/index.js';
import { generateIntentDocument } from '../../core/contracts/intent.js';

interface RefreshOptions {
  keepConfig: boolean;
}

export async function refreshCommand(options: RefreshOptions): Promise<void> {
  const cwd = process.cwd();
  const whiterosePath = join(cwd, '.whiterose');

  // Check if initialized
  if (!existsSync(whiterosePath)) {
    p.log.error('whiterose is not initialized in this directory.');
    p.log.info('Run "whiterose init" first.');
    process.exit(1);
  }

  p.intro(chalk.red('whiterose') + chalk.dim(' - refreshing understanding'));

  // Load config
  const config = await loadConfig(cwd);

  // Scan codebase
  const scanSpinner = p.spinner();
  scanSpinner.start('Scanning codebase...');
  const files = await scanCodebase(cwd, config);
  scanSpinner.stop(`Found ${files.length} source files`);

  // Generate new understanding
  const understandingSpinner = p.spinner();
  understandingSpinner.start('Regenerating understanding with AI...');

  try {
    const executor = getExecutor(config.provider);
    const scanner = new CoreScanner(executor, {}, {
      onProgress: (message: string) => {
        if (message.trim()) {
          understandingSpinner.message(message);
        }
      },
    });
    const understanding = await scanner.generateUnderstanding(files);

    // Write new understanding
    writeFileSync(
      join(whiterosePath, 'cache', 'understanding.json'),
      JSON.stringify(understanding, null, 2),
      'utf-8'
    );

    // Regenerate intent.md
    const intentDoc = generateIntentDocument(understanding);
    writeFileSync(join(whiterosePath, 'intent.md'), intentDoc, 'utf-8');

    // Reset file hashes
    writeFileSync(
      join(whiterosePath, 'cache', 'file-hashes.json'),
      JSON.stringify({ version: '1', fileHashes: [], lastFullScan: new Date().toISOString() }, null, 2),
      'utf-8'
    );

    understandingSpinner.stop('Understanding regenerated');
  } catch (error) {
    understandingSpinner.stop('Failed to regenerate understanding');
    p.log.error(String(error));
    process.exit(1);
  }

  p.outro(chalk.green('Refresh complete!'));
}
