/**
 * ASCII card renderer for scan results
 * Creates a screenshot-friendly summary card
 */

import chalk from 'chalk';
import { formatDuration } from './progress.js';

export interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface ScanMeta {
  repoName: string;
  provider: string;
  duration: number; // ms
  filesScanned: number;
  linesOfCode: number;
}

export interface CardData {
  meta: ScanMeta;
  bugs: SeverityBreakdown;
  smells: SeverityBreakdown;
  reportPath: string;
}

const BOX = {
  topLeft: '\u250c',
  topRight: '\u2510',
  bottomLeft: '\u2514',
  bottomRight: '\u2518',
  horizontal: '\u2500',
  vertical: '\u2502',
  teeRight: '\u251c',
  teeLeft: '\u2524',
};

function line(char: string, width: number): string {
  return char.repeat(width);
}

function padRight(str: string, width: number): string {
  // Strip ANSI codes for length calculation
  // eslint-disable-next-line no-control-regex
  const stripped = str.replace(/\u001b\[\d+(;\d+)*m/g, '');
  const padding = Math.max(0, width - stripped.length);
  return str + ' '.repeat(padding);
}

function row(content: string, width: number): string {
  return BOX.vertical + '  ' + padRight(content, width - 4) + '  ' + BOX.vertical;
}

function divider(width: number): string {
  return BOX.teeRight + line(BOX.horizontal, width) + BOX.teeLeft;
}

function topBorder(width: number): string {
  return BOX.topLeft + line(BOX.horizontal, width) + BOX.topRight;
}

function bottomBorder(width: number): string {
  return BOX.bottomLeft + line(BOX.horizontal, width) + BOX.bottomRight;
}

function severityDot(severity: 'critical' | 'high' | 'medium' | 'low'): string {
  const colors: Record<string, (s: string) => string> = {
    critical: chalk.red,
    high: chalk.yellow,
    medium: chalk.blue,
    low: chalk.dim,
  };
  return colors[severity]('\u25cf');
}

function formatNumber(n: number): string {
  return String(n).padStart(3);
}

/**
 * Render a scan result card
 *
 * ┌─────────────────────────────────────────────────────────────┐
 * │  WHITEROSE SCAN COMPLETE                                    │
 * ├─────────────────────────────────────────────────────────────┤
 * │  Repository    my-project                                   │
 * │  Provider      claude-code                                  │
 * │  Duration      17m 11s                                      │
 * │  Files         116 files | 24,892 LoC                       │
 * ├─────────────────────────────────────────────────────────────┤
 * │  BUGS                          SMELLS                       │
 * │  ● Critical    3               ● Critical    0              │
 * │  ● High       12               ● High        5              │
 * │  ● Medium     30               ● Medium     20              │
 * │  ● Low        17               ● Low        12              │
 * │  ─────────────                 ─────────────                │
 * │  Total        62               Total        37              │
 * ├─────────────────────────────────────────────────────────────┤
 * │  Reports: ./whiterose-output/bugs.md                        │
 * │  Run: whiterose fix                                         │
 * └─────────────────────────────────────────────────────────────┘
 */
export function renderScanCard(data: CardData): string {
  const width = 61; // Inner width (excluding border chars)
  const lines: string[] = [];

  // Title
  lines.push(topBorder(width));
  lines.push(row(chalk.bold.red('WHITEROSE SCAN COMPLETE'), width));
  lines.push(divider(width));

  // Meta section
  const locFormatted = data.meta.linesOfCode.toLocaleString();
  lines.push(row(`${chalk.dim('Repository')}    ${data.meta.repoName}`, width));
  lines.push(row(`${chalk.dim('Provider')}      ${data.meta.provider}`, width));
  lines.push(row(`${chalk.dim('Duration')}      ${formatDuration(data.meta.duration)}`, width));
  lines.push(row(`${chalk.dim('Files')}         ${data.meta.filesScanned} files | ${locFormatted} LoC`, width));
  lines.push(divider(width));

  // Bug/Smell breakdown header
  lines.push(row(`${chalk.bold('BUGS')}                          ${chalk.bold('SMELLS')}`, width));

  // Severity rows (side by side)
  const severities: Array<'critical' | 'high' | 'medium' | 'low'> = ['critical', 'high', 'medium', 'low'];
  for (const sev of severities) {
    const bugLine = `${severityDot(sev)} ${sev.charAt(0).toUpperCase() + sev.slice(1).padEnd(8)} ${formatNumber(data.bugs[sev])}`;
    const smellLine = `${severityDot(sev)} ${sev.charAt(0).toUpperCase() + sev.slice(1).padEnd(8)} ${formatNumber(data.smells[sev])}`;
    lines.push(row(`${bugLine}               ${smellLine}`, width));
  }

  // Totals divider
  lines.push(row(`${chalk.dim('\u2500'.repeat(13))}                 ${chalk.dim('\u2500'.repeat(13))}`, width));

  // Totals
  const bugTotal = `Total        ${formatNumber(data.bugs.total)}`;
  const smellTotal = `Total        ${formatNumber(data.smells.total)}`;
  lines.push(row(`${chalk.bold(bugTotal)}               ${chalk.bold(smellTotal)}`, width));
  lines.push(divider(width));

  // Footer
  lines.push(row(`${chalk.dim('Reports:')} ${chalk.cyan(data.reportPath)}`, width));
  if (data.bugs.total > 0 || data.smells.total > 0) {
    lines.push(row(`${chalk.dim('Run:')} ${chalk.cyan('whiterose fix')}`, width));
  }
  lines.push(bottomBorder(width));

  return lines.join('\n');
}

/**
 * Render a minimal status card (for status command when no recent scan)
 */
export function renderStatusCard(
  repoName: string,
  provider: string,
  totalBugs: number,
  totalSmells: number,
  lastScanDate?: string
): string {
  const width = 45;
  const lines: string[] = [];

  lines.push(topBorder(width));
  lines.push(row(chalk.bold.red('WHITEROSE STATUS'), width));
  lines.push(divider(width));
  lines.push(row(`${chalk.dim('Repository')}  ${repoName}`, width));
  lines.push(row(`${chalk.dim('Provider')}    ${provider}`, width));
  if (lastScanDate) {
    lines.push(row(`${chalk.dim('Last scan')}   ${lastScanDate}`, width));
  }
  lines.push(divider(width));
  lines.push(row(`${chalk.bold('Open bugs:')}   ${totalBugs}`, width));
  lines.push(row(`${chalk.bold('Open smells:')} ${totalSmells}`, width));
  lines.push(bottomBorder(width));

  return lines.join('\n');
}
