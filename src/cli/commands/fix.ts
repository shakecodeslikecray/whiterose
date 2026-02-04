import * as p from '@clack/prompts';
import chalk from 'chalk';
import { existsSync, readFileSync, readdirSync } from 'fs';
import { join, resolve, isAbsolute } from 'path';
import { execa } from 'execa';
import { Bug, ProviderType } from '../../types.js';
import { loadConfig } from '../../core/config.js';
import { startFixTUI } from '../../tui/index.js';
import { applyFix } from '../../core/fixer.js';
import { loadAccumulatedBugs, removeBugFromAccumulated } from '../../core/bug-merger.js';
import { detectProvider } from '../../providers/detect.js';

interface FixOptions {
  dryRun: boolean;
  branch?: string;
  sarif?: string;
  github?: string;
  describe?: boolean;
  provider?: string;
}

export async function fixCommand(bugId: string | undefined, options: FixOptions): Promise<void> {
  const cwd = process.cwd();
  const whiterosePath = join(cwd, '.whiterose');

  // ─────────────────────────────────────────────────────────────
  // Provider Selection (first thing!)
  // ─────────────────────────────────────────────────────────────
  let selectedProvider: ProviderType;

  if (options.provider) {
    // Use CLI-specified provider
    selectedProvider = options.provider as ProviderType;
    p.log.info(`Using provider: ${chalk.cyan(selectedProvider)}`);
  } else {
    // Detect and prompt for provider
    const detectSpinner = p.spinner();
    detectSpinner.start('Detecting LLM providers...');

    const availableProviders = await detectProvider();

    if (availableProviders.length === 0) {
      detectSpinner.stop('No providers found');
      p.log.error('No LLM providers detected on your system.');
      console.log();
      console.log(chalk.dim('  Install one of:'));
      console.log(chalk.dim('  - claude-code: ') + chalk.cyan('npm install -g @anthropic-ai/claude-code'));
      console.log(chalk.dim('  - gemini: ') + chalk.cyan('npm install -g @google/gemini-cli'));
      console.log(chalk.dim('  - aider: ') + chalk.cyan('pip install aider-chat'));
      console.log();
      process.exit(1);
    }

    detectSpinner.stop(`Found ${availableProviders.length} provider(s)`);

    if (availableProviders.length === 1) {
      selectedProvider = availableProviders[0];
      p.log.info(`Using ${chalk.cyan(selectedProvider)}`);
    } else {
      const providerChoice = await p.select({
        message: 'Select LLM provider for fixing bugs',
        options: availableProviders.map((provider) => ({
          value: provider,
          label: provider,
          hint: provider === 'claude-code' ? 'recommended' : undefined,
        })),
      });

      if (p.isCancel(providerChoice)) {
        p.cancel('Cancelled.');
        process.exit(0);
      }

      selectedProvider = providerChoice as ProviderType;
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Source 1: External SARIF file
  // ─────────────────────────────────────────────────────────────
  if (options.sarif) {
    const sarifPath = isAbsolute(options.sarif) ? options.sarif : resolve(cwd, options.sarif);

    if (!existsSync(sarifPath)) {
      p.log.error(`SARIF file not found: ${sarifPath}`);
      process.exit(1);
    }

    p.intro(chalk.red('whiterose') + chalk.dim(' - fixing bugs from external SARIF'));

    const bugs = loadBugsFromSarif(sarifPath);
    if (bugs.length === 0) {
      p.log.success('No bugs found in SARIF file!');
      process.exit(0);
    }

    p.log.info(`Loaded ${bugs.length} bugs from ${options.sarif}`);

    // Load config if available (for fix options), or use defaults
    const baseConfig = existsSync(whiterosePath)
      ? await loadConfig(cwd)
      : getDefaultConfig();
    const config = { ...baseConfig, provider: selectedProvider };

    return await processBugList(bugs, config, options, bugId);
  }

  // ─────────────────────────────────────────────────────────────
  // Source 2: GitHub issue
  // ─────────────────────────────────────────────────────────────
  if (options.github) {
    p.intro(chalk.red('whiterose') + chalk.dim(' - fixing bug from GitHub issue'));

    const bug = await loadBugFromGitHub(options.github, cwd);
    if (!bug) {
      p.log.error('Failed to parse GitHub issue as a bug');
      process.exit(1);
    }

    p.log.info(`Loaded bug from GitHub: ${bug.title}`);

    const baseConfig = existsSync(whiterosePath)
      ? await loadConfig(cwd)
      : getDefaultConfig();
    const config = { ...baseConfig, provider: selectedProvider };

    return await fixSingleBug(bug, config, options);
  }

  // ─────────────────────────────────────────────────────────────
  // Source 3: Manual description (interactive)
  // ─────────────────────────────────────────────────────────────
  if (options.describe) {
    p.intro(chalk.red('whiterose') + chalk.dim(' - fixing manually described bug'));

    const bug = await collectManualBugDescription(cwd);
    if (!bug) {
      p.cancel('Bug description cancelled.');
      process.exit(0);
    }

    const baseConfig = existsSync(whiterosePath)
      ? await loadConfig(cwd)
      : getDefaultConfig();
    const config = { ...baseConfig, provider: selectedProvider };

    return await fixSingleBug(bug, config, options);
  }

  // ─────────────────────────────────────────────────────────────
  // Source 4: Default - accumulated whiterose scan results
  // ─────────────────────────────────────────────────────────────

  // Check if initialized
  if (!existsSync(whiterosePath)) {
    p.log.error('whiterose is not initialized in this directory.');
    p.log.info('Run "whiterose init" first, or use:');
    p.log.info('  --sarif <path>   Fix bugs from an external SARIF file');
    p.log.info('  --github <url>   Fix bug from a GitHub issue');
    p.log.info('  --describe       Manually describe a bug to fix');
    process.exit(1);
  }

  // Load config and override provider with selected one
  const baseConfig = await loadConfig(cwd);
  const config = { ...baseConfig, provider: selectedProvider };

  // Load accumulated bugs (union of all scans)
  const accumulatedBugs = loadAccumulatedBugs(cwd);

  if (accumulatedBugs.bugs.length > 0) {
    p.intro(chalk.red('whiterose') + chalk.dim(' - fixing accumulated bugs'));
    p.log.info(`Found ${accumulatedBugs.bugs.length} accumulated bugs from all scans`);
    return await processBugList(accumulatedBugs.bugs, config, options, bugId, cwd);
  }

  // Fallback to SARIF if no accumulated bugs (legacy support)
  const reportsDir = join(whiterosePath, 'reports');
  if (!existsSync(reportsDir)) {
    p.log.error('No scan results found. Run "whiterose scan" first.');
    p.log.info('Or use --sarif, --github, or --describe for external bugs.');
    process.exit(1);
  }

  // Get latest SARIF file
  const reports = readdirSync(reportsDir)
    .filter((f) => f.endsWith('.sarif'))
    .sort()
    .reverse();

  if (reports.length === 0) {
    p.log.error('No scan results found. Run "whiterose scan" first.');
    p.log.info('Or use --sarif, --github, or --describe for external bugs.');
    process.exit(1);
  }

  const latestReport = join(reportsDir, reports[0]);
  const bugs = loadBugsFromSarif(latestReport);

  return await processBugList(bugs, config, options, bugId);
}

// ─────────────────────────────────────────────────────────────
// Bug Loading Functions
// ─────────────────────────────────────────────────────────────

function loadBugsFromSarif(sarifPath: string): Bug[] {
  let sarif: any;
  try {
    sarif = JSON.parse(readFileSync(sarifPath, 'utf-8'));
  } catch (error) {
    throw new Error(`Failed to parse SARIF file: ${sarifPath}. File may be corrupted or malformed.`);
  }

  return sarif.runs?.[0]?.results?.map((r: any, i: number) => {
    // Try to extract full bug info from SARIF properties if available
    const props = r.properties || {};

    return {
      id: r.ruleId || `WR-${String(i + 1).padStart(3, '0')}`,
      title: r.message?.text || 'Unknown bug',
      description: r.message?.markdown || r.message?.text || '',
      file: r.locations?.[0]?.physicalLocation?.artifactLocation?.uri || 'unknown',
      line: r.locations?.[0]?.physicalLocation?.region?.startLine || 0,
      endLine: r.locations?.[0]?.physicalLocation?.region?.endLine,
      kind: props.kind || 'bug',
      severity: mapSarifLevel(r.level),
      category: props.category || 'logic-error',
      confidence: {
        overall: props.confidence || 'medium',
        codePathValidity: props.codePathValidity || 0.8,
        reachability: props.reachability || 0.8,
        intentViolation: props.intentViolation || false,
        staticToolSignal: props.staticToolSignal || false,
        adversarialSurvived: props.adversarialSurvived || false,
      },
      codePath: r.codeFlows?.[0]?.threadFlows?.[0]?.locations?.map((loc: any, idx: number) => ({
        step: idx + 1,
        file: loc.location?.physicalLocation?.artifactLocation?.uri || '',
        line: loc.location?.physicalLocation?.region?.startLine || 0,
        code: '',
        explanation: loc.message?.text || '',
      })) || [],
      evidence: props.evidence || [],
      suggestedFix: props.suggestedFix,
      createdAt: new Date().toISOString(),
      status: 'open',
    };
  }) || [];
}

async function loadBugFromGitHub(issueUrl: string, cwd: string): Promise<Bug | null> {
  try {
    // Parse the issue URL: https://github.com/owner/repo/issues/123
    const match = issueUrl.match(/github\.com\/([^/]+)\/([^/]+)\/issues\/(\d+)/);
    if (!match) {
      p.log.error('Invalid GitHub issue URL format. Expected: https://github.com/owner/repo/issues/123');
      return null;
    }

    const [, owner, repo, issueNumber] = match;

    // Use gh CLI to fetch issue details
    const { stdout } = await execa('gh', [
      'issue', 'view', issueNumber,
      '--repo', `${owner}/${repo}`,
      '--json', 'title,body,labels'
    ], { cwd });

    const issue = JSON.parse(stdout);

    // Parse file and line from issue body (common patterns)
    const fileMatch = issue.body?.match(/(?:file|path|location):\s*[`"]?([^\s`"]+)[`"]?/i) ||
                      issue.body?.match(/```[\w]*\n(?:\/\/|#)\s*([^\s:]+):(\d+)/);
    const lineMatch = issue.body?.match(/(?:line|L|:)(\d+)/);

    // Determine severity from labels
    let severity: 'critical' | 'high' | 'medium' | 'low' = 'medium';
    const labels = issue.labels?.map((l: any) => l.name.toLowerCase()) || [];
    if (labels.some((l: string) => l.includes('critical') || l.includes('security'))) {
      severity = 'critical';
    } else if (labels.some((l: string) => l.includes('bug') || l.includes('high'))) {
      severity = 'high';
    } else if (labels.some((l: string) => l.includes('low') || l.includes('minor'))) {
      severity = 'low';
    }

    // Determine category from labels (using valid BugCategory values)
    let category: Bug['category'] = 'logic-error';
    if (labels.some((l: string) => l.includes('security') || l.includes('injection') || l.includes('xss') || l.includes('sql'))) {
      category = 'injection';
    } else if (labels.some((l: string) => l.includes('auth') || l.includes('permission'))) {
      category = 'auth-bypass';
    } else if (labels.some((l: string) => l.includes('null') || l.includes('undefined'))) {
      category = 'null-reference';
    } else if (labels.some((l: string) => l.includes('async') || l.includes('race') || l.includes('promise'))) {
      category = 'async-issue';
    } else if (labels.some((l: string) => l.includes('leak') || l.includes('memory'))) {
      category = 'resource-leak';
    }

    return {
      id: `GH-${issueNumber}`,
      title: issue.title,
      description: issue.body || issue.title,
      file: fileMatch?.[1] || '',
      line: parseInt(lineMatch?.[1] || '1', 10),
      kind: 'bug',
      severity,
      category,
      confidence: {
        overall: 'medium',
        codePathValidity: 0.5,
        reachability: 0.5,
        intentViolation: false,
        staticToolSignal: false,
        adversarialSurvived: false,
      },
      codePath: [],
      evidence: [`GitHub issue: ${issueUrl}`],
      createdAt: new Date().toISOString(),
      status: 'open',
    };
  } catch (error: any) {
    if (error.message?.includes('gh')) {
      p.log.error('GitHub CLI (gh) is required for --github option.');
      p.log.info('Install it: https://cli.github.com/');
    } else {
      p.log.error(`Failed to fetch GitHub issue: ${error.message}`);
    }
    return null;
  }
}

async function collectManualBugDescription(cwd: string): Promise<Bug | null> {
  // Get file path
  const file = await p.text({
    message: 'File path containing the bug:',
    placeholder: 'src/components/Button.tsx',
    validate: (value) => {
      if (!value) return 'File path is required';
      const fullPath = isAbsolute(value) ? value : resolve(cwd, value);
      if (!existsSync(fullPath)) return `File not found: ${value}`;
      return undefined;
    },
  });

  if (p.isCancel(file)) return null;

  // Get line number
  const lineStr = await p.text({
    message: 'Line number (approximate is fine):',
    placeholder: '42',
    validate: (value) => {
      if (!value) return 'Line number is required';
      if (isNaN(parseInt(value, 10))) return 'Must be a number';
      return undefined;
    },
  });

  if (p.isCancel(lineStr)) return null;

  // Get bug title
  const title = await p.text({
    message: 'Bug title (brief description):',
    placeholder: 'Null reference when user is not logged in',
  });

  if (p.isCancel(title)) return null;

  // Get detailed description
  const description = await p.text({
    message: 'Detailed description (what happens, how to trigger):',
    placeholder: 'When user.profile is accessed before login check, TypeError is thrown',
  });

  if (p.isCancel(description)) return null;

  // Get severity
  const severity = await p.select({
    message: 'Bug severity:',
    options: [
      { value: 'critical', label: 'Critical', hint: 'security issue, data loss' },
      { value: 'high', label: 'High', hint: 'crash, incorrect behavior' },
      { value: 'medium', label: 'Medium', hint: 'bug with workaround' },
      { value: 'low', label: 'Low', hint: 'minor issue' },
    ],
    initialValue: 'medium',
  });

  if (p.isCancel(severity)) return null;

  // Get category (using valid BugCategory enum values)
  const category = await p.select({
    message: 'Bug category:',
    options: [
      { value: 'logic-error', label: 'Logic Error' },
      { value: 'null-reference', label: 'Null Reference' },
      { value: 'injection', label: 'Injection (SQL, XSS, etc.)' },
      { value: 'auth-bypass', label: 'Auth Bypass' },
      { value: 'async-issue', label: 'Async/Race Condition' },
      { value: 'boundary-error', label: 'Boundary/Edge Case' },
      { value: 'type-coercion', label: 'Type Coercion' },
      { value: 'data-validation', label: 'Data Validation' },
      { value: 'resource-leak', label: 'Resource Leak' },
      { value: 'concurrency', label: 'Concurrency' },
      { value: 'intent-violation', label: 'Intent Violation' },
      { value: 'secrets-exposure', label: 'Secrets Exposure' },
    ],
    initialValue: 'logic-error',
  });

  if (p.isCancel(category)) return null;

  const filePath = isAbsolute(file) ? file : resolve(cwd, file);
  const relativePath = filePath.startsWith(cwd) ? filePath.slice(cwd.length + 1) : filePath;

  return {
    id: `MANUAL-${Date.now()}`,
    title: title || 'Manual bug',
    description: description || title || 'Manual bug',
    file: relativePath,
    line: parseInt(lineStr || '1', 10),
    kind: 'bug',
    severity: severity as Bug['severity'],
    category: category as Bug['category'],
    confidence: {
      overall: 'high', // User-reported bugs are high confidence
      codePathValidity: 1,
      reachability: 1,
      intentViolation: true,
      staticToolSignal: false,
      adversarialSurvived: false,
    },
    codePath: [],
    evidence: ['Manually reported by user'],
    createdAt: new Date().toISOString(),
    status: 'open',
  };
}

function getDefaultConfig() {
  // Return minimal config for external bug sources when whiterose isn't initialized
  return {
    version: '1',
    provider: 'claude-code' as const,
    include: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    exclude: ['node_modules', 'dist', 'build'],
    priorities: {},
    categories: ['injection', 'auth-bypass', 'secrets-exposure', 'null-reference', 'boundary-error', 'resource-leak', 'async-issue', 'logic-error', 'data-validation', 'type-coercion', 'concurrency', 'intent-violation'],
    minConfidence: 'low' as const,
    staticAnalysis: { typescript: true, eslint: true },
    output: { sarif: true, markdown: true, sarifPath: '.whiterose/reports', markdownPath: 'BUGS.md' },
  };
}

// ─────────────────────────────────────────────────────────────
// Bug Processing Functions
// ─────────────────────────────────────────────────────────────

async function processBugList(
  bugs: Bug[],
  config: any,
  options: FixOptions,
  bugId: string | undefined,
  cwd?: string
): Promise<void> {
  if (bugs.length === 0) {
    p.log.success('No bugs to fix!');
    process.exit(0);
  }

  // If specific bug ID provided, fix just that bug
  if (bugId) {
    const bug = bugs.find((b) => b.id === bugId || b.id.toLowerCase() === bugId.toLowerCase());
    if (!bug) {
      p.log.error(`Bug ${bugId} not found.`);
      p.log.info('Available bugs: ' + bugs.map((b) => b.id).join(', '));
      process.exit(1);
    }

    return await fixSingleBug(bug, config, options, cwd);
  }

  // Launch interactive TUI (pass cwd for bug removal after fix)
  try {
    await startFixTUI(bugs, config, options, cwd);
  } catch (error: any) {
    // If Ink fails (e.g., not a TTY), fall back to simple mode
    if (error.message?.includes('stdin') || error.message?.includes('TTY')) {
      p.log.warn('Interactive mode not available. Use "whiterose fix <bug-id>" to fix specific bugs.');
      p.log.info('Available bugs:');
      for (const bug of bugs) {
        const severityColor = bug.severity === 'critical' ? 'red' : bug.severity === 'high' ? 'yellow' : 'blue';
        console.log(`  ${chalk[severityColor]('●')} ${bug.id}: ${bug.title}`);
      }
    } else {
      throw error;
    }
  }
}

async function fixSingleBug(bug: Bug, config: any, options: FixOptions, cwd?: string): Promise<void> {
  p.intro(chalk.red('whiterose') + chalk.dim(' - fixing bug'));

  // Check if file is specified (needed for fixing)
  if (!bug.file) {
    const file = await p.text({
      message: 'File path containing the bug (required for fix):',
      placeholder: 'src/components/Button.tsx',
    });

    if (p.isCancel(file) || !file) {
      p.cancel('Fix cancelled - file path required.');
      process.exit(0);
    }

    bug.file = file;
  }

  // Show bug details
  console.log();
  console.log(chalk.bold(`  ${bug.id}: ${bug.title}`));
  console.log(`  ${chalk.dim('File:')} ${bug.file}:${bug.line}`);
  console.log(`  ${chalk.dim('Severity:')} ${bug.severity}`);
  console.log();
  console.log(`  ${bug.description}`);
  console.log();

  if (bug.suggestedFix) {
    console.log(chalk.dim('  Suggested fix:'));
    console.log(`  ${chalk.green(bug.suggestedFix)}`);
    console.log();
  }

  // Confirm fix
  if (!options.dryRun) {
    const confirm = await p.confirm({
      message: 'Apply this fix?',
      initialValue: true,
    });

    if (p.isCancel(confirm) || !confirm) {
      p.cancel('Fix cancelled.');
      process.exit(0);
    }
  }

  // Apply fix
  const spinner = p.spinner();
  spinner.start(options.dryRun ? 'Generating fix preview...' : 'Applying fix...');

  try {
    const result = await applyFix(bug, config, options);

    if (result.success) {
      spinner.stop(options.dryRun ? 'Fix preview generated' : 'Fix applied');

      if (result.diff) {
        console.log();
        console.log(chalk.dim('  Changes:'));
        for (const line of result.diff.split('\n')) {
          if (line.startsWith('+')) {
            console.log(chalk.green(`  ${line}`));
          } else if (line.startsWith('-')) {
            console.log(chalk.red(`  ${line}`));
          } else {
            console.log(chalk.dim(`  ${line}`));
          }
        }
        console.log();
      }

      if (result.branchName) {
        p.log.info(`Changes committed to branch: ${result.branchName}`);
      }

      // Remove bug from accumulated list after successful fix (not dry-run)
      if (!options.dryRun && cwd) {
        const removed = removeBugFromAccumulated(cwd, bug.id);
        if (removed) {
          p.log.info(`Bug ${bug.id} removed from accumulated bug list`);
        }
      }

      p.outro(chalk.green('Fix complete!'));
    } else {
      spinner.stop('Fix failed');
      p.log.error(result.error || 'Unknown error');
      process.exit(1);
    }
  } catch (error: any) {
    spinner.stop('Fix failed');
    p.log.error(error.message);
    process.exit(1);
  }
}

function mapSarifLevel(level: string): 'critical' | 'high' | 'medium' | 'low' {
  switch (level) {
    case 'error':
      return 'high';
    case 'warning':
      return 'medium';
    case 'note':
      return 'low';
    default:
      return 'medium';
  }
}
