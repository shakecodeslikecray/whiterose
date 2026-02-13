import * as p from '@clack/prompts';
import chalk from 'chalk';
import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync } from 'fs';
import { join } from 'path';
import { loadUnderstanding } from '../../core/config.js';
import { generateRiskProfile } from '../../core/risk-profiler.js';
import type { RiskProfile } from '../../types.js';

interface ProfileOptions {
  json?: boolean;
}

export async function profileCommand(options: ProfileOptions): Promise<void> {
  const cwd = process.cwd();
  const whiterosePath = join(cwd, '.whiterose');

  if (!existsSync(whiterosePath)) {
    p.log.error('whiterose is not initialized in this directory.');
    p.log.info('Run "whiterose init" first.');
    process.exit(1);
  }

  const spinner = p.spinner();
  spinner.start('Loading codebase understanding...');

  const understanding = await loadUnderstanding(cwd);
  if (!understanding) {
    spinner.stop('No understanding found');
    p.log.error('No understanding.json found. Run "whiterose init" or "whiterose refresh" first.');
    process.exit(1);
  }

  spinner.stop('Understanding loaded');

  // Read package.json for dependency detection
  let packageJsonDeps: Record<string, string> | undefined;
  const packageJsonPath = join(cwd, 'package.json');
  if (existsSync(packageJsonPath)) {
    try {
      const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
      packageJsonDeps = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {}),
      };
    } catch {
      // Non-fatal
    }
  }

  // Collect project files from understanding + scan root for config/env files
  const projectFiles = understanding.features.flatMap(f => f.relatedFiles || []);
  try {
    const rootFiles = readdirSync(cwd);
    for (const file of rootFiles) {
      if (/^\.env($|\.)/.test(file) || /^config\.(json|yml|yaml|toml)$/.test(file) || file === 'openapi.json' || file === 'openapi.yml' || file === 'openapi.yaml' || file === 'swagger.json' || file === 'swagger.yml' || file === 'swagger.yaml') {
        projectFiles.push(file);
      }
    }
  } catch {
    // Non-fatal: can't read directory
  }

  spinner.start('Generating risk profile...');

  const profile = generateRiskProfile(understanding, projectFiles, packageJsonDeps);

  // Save profile
  const cachePath = join(whiterosePath, 'cache');
  mkdirSync(cachePath, { recursive: true });
  const profilePath = join(whiterosePath, 'risk-profile.json');
  writeFileSync(profilePath, JSON.stringify(profile, null, 2), 'utf-8');

  spinner.stop('Risk profile generated');

  if (options.json) {
    console.log(JSON.stringify(profile, null, 2));
    return;
  }

  // Human-readable output
  displayProfile(profile);

  console.log();
  p.log.success(`Saved to ${chalk.cyan('.whiterose/risk-profile.json')}`);
  p.log.info(`Run ${chalk.cyan('whiterose scan --full')} to use this profile.`);
}

function displayProfile(profile: RiskProfile): void {
  console.log();

  // Domains
  if (profile.domains.length > 0) {
    p.log.step(chalk.bold('Detected Domains'));
    for (const domain of profile.domains) {
      const icon = getDomainIcon(domain);
      console.log(`  ${icon} ${chalk.cyan(domain)}`);
    }
  } else {
    p.log.info('No specific domains detected');
  }

  // Sensitive data
  if (profile.sensitiveDataTypes.length > 0) {
    console.log();
    p.log.step(chalk.bold('Sensitive Data Types'));
    for (const dt of profile.sensitiveDataTypes) {
      console.log(`  ${chalk.yellow('\u25cf')} ${dt}`);
    }
  }

  // Hot paths
  if (profile.hotPaths.length > 0) {
    console.log();
    p.log.step(chalk.bold('Hot Paths') + chalk.dim(' (files touching 2+ domains)'));
    for (const hp of profile.hotPaths) {
      const color = hp.riskLevel === 'critical' ? chalk.red : hp.riskLevel === 'high' ? chalk.yellow : chalk.blue;
      console.log(`  ${color('[' + hp.riskLevel + ']')} ${hp.file}`);
      console.log(`    ${chalk.dim(hp.reason)}`);
    }
  }

  // Custom passes
  if (profile.customPasses.length > 0) {
    console.log();
    p.log.step(chalk.bold('Custom Passes') + chalk.dim(` (${profile.customPasses.length} domain-specific)`));
    for (const pass of profile.customPasses) {
      const phaseColor = pass.phase === 'unit' ? chalk.green : pass.phase === 'integration' ? chalk.blue : chalk.magenta;
      console.log(`  ${chalk.cyan('+')} ${pass.id} ${phaseColor('[' + pass.phase + ']')}`);
    }
  }

  // Skipped passes
  if (profile.skippedPasses.length > 0) {
    console.log();
    p.log.step(chalk.bold('Skipped Passes') + chalk.dim(` (${profile.skippedPasses.length} not relevant)`));
    for (const skip of profile.skippedPasses) {
      console.log(`  ${chalk.dim('-')} ${skip.passName} ${chalk.dim('(' + skip.reason + ')')}`);
    }
  }
}

function getDomainIcon(domain: string): string {
  const icons: Record<string, string> = {
    'payments': '\u25b6',
    'auth': '\u25b6',
    'file-upload': '\u25b6',
    'messaging': '\u25b6',
    'search': '\u25b6',
    'analytics': '\u25b6',
    'admin': '\u25b6',
    'api': '\u25b6',
    'database': '\u25b6',
    'realtime': '\u25b6',
  };
  return icons[domain] || '\u25b6';
}
