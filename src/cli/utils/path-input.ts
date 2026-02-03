import { readdirSync, statSync, existsSync } from 'fs';
import { join, dirname, basename, resolve } from 'path';
import chalk from 'chalk';
import * as readline from 'readline';

/**
 * Get directory completions for a partial path
 */
function getPathCompletions(partial: string): string[] {
  try {
    if (!partial) partial = '.';

    const resolved = resolve(partial);
    let dir: string;
    let prefix: string;

    // Check if partial is a directory (ends with / or is a directory)
    if (partial.endsWith('/') || (existsSync(resolved) && statSync(resolved).isDirectory())) {
      dir = resolved;
      prefix = '';
    } else {
      dir = dirname(resolved);
      prefix = basename(partial);
    }

    if (!existsSync(dir)) {
      return [];
    }

    const entries = readdirSync(dir, { withFileTypes: true });
    const matches = entries
      .filter((entry) => entry.isDirectory())
      .filter((entry) => entry.name.toLowerCase().startsWith(prefix.toLowerCase()))
      .filter((entry) => !entry.name.startsWith('.') || prefix.startsWith('.'))
      .map((entry) => {
        if (partial.endsWith('/') || prefix === '') {
          return partial + entry.name + '/';
        }
        const base = partial.slice(0, partial.length - prefix.length);
        return base + entry.name + '/';
      })
      .sort();

    return matches;
  } catch {
    return [];
  }
}

/**
 * Find longest common prefix among strings
 */
function longestCommonPrefix(strings: string[]): string {
  if (strings.length === 0) return '';
  if (strings.length === 1) return strings[0];

  let prefix = strings[0];
  for (let i = 1; i < strings.length; i++) {
    while (!strings[i].startsWith(prefix)) {
      prefix = prefix.slice(0, -1);
      if (prefix === '') return '';
    }
  }
  return prefix;
}

export interface PathInputOptions {
  message: string;
  defaultValue?: string;
  validate?: (path: string) => string | undefined;
}

/**
 * Prompt for a path with Tab completion (bash-style)
 */
export function pathInput(options: PathInputOptions): Promise<string | null> {
  return new Promise((resolvePromise) => {
    const { message, defaultValue = '', validate } = options;

    // Display prompt
    const promptText = chalk.cyan('◆') + ' ' + chalk.bold(message);
    const hint = defaultValue ? chalk.dim(` (default: ${defaultValue})`) : '';
    const tabHint = chalk.dim(' [Tab to autocomplete]');

    process.stdout.write(promptText + hint + tabHint + '\n');
    process.stdout.write(chalk.cyan('│') + ' ');

    let input = '';
    let cursorPos = 0;

    // Enable raw mode for key-by-key input
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
    }
    process.stdin.resume();
    process.stdin.setEncoding('utf8');

    const redrawLine = () => {
      // Clear current line and redraw
      readline.clearLine(process.stdout, 0);
      readline.cursorTo(process.stdout, 0);
      process.stdout.write(chalk.cyan('│') + ' ' + input);
      // Position cursor
      readline.cursorTo(process.stdout, 2 + cursorPos);
    };

    const cleanup = () => {
      if (process.stdin.isTTY) {
        process.stdin.setRawMode(false);
      }
      process.stdin.pause();
      process.stdin.removeAllListeners('data');
    };

    const finish = (result: string | null) => {
      cleanup();
      console.log(); // New line after input
      resolvePromise(result);
    };

    process.stdin.on('data', (key: string) => {
      const code = key.charCodeAt(0);

      // Ctrl+C - cancel
      if (code === 3) {
        console.log();
        finish(null);
        return;
      }

      // Enter - submit
      if (code === 13) {
        const finalPath = input.trim() || defaultValue;

        if (validate) {
          const error = validate(finalPath);
          if (error) {
            console.log();
            process.stdout.write(chalk.red('│') + ' ' + chalk.red(error) + '\n');
            process.stdout.write(chalk.cyan('│') + ' ' + input);
            return;
          }
        }

        finish(finalPath);
        return;
      }

      // Tab - autocomplete
      if (code === 9) {
        const completions = getPathCompletions(input || '.');

        if (completions.length === 1) {
          // Single match - complete it
          input = completions[0];
          cursorPos = input.length;
          redrawLine();
        } else if (completions.length > 1) {
          // Multiple matches - complete common prefix and show options
          const common = longestCommonPrefix(completions);
          if (common.length > input.length) {
            input = common;
            cursorPos = input.length;
            redrawLine();
          } else {
            // Show available completions
            console.log();
            const maxShow = 10;
            const shown = completions.slice(0, maxShow);
            process.stdout.write(chalk.dim('│ ') + shown.map(c => chalk.cyan(basename(c.slice(0, -1)))).join('  '));
            if (completions.length > maxShow) {
              process.stdout.write(chalk.dim(` ... +${completions.length - maxShow} more`));
            }
            console.log();
            process.stdout.write(chalk.cyan('│') + ' ' + input);
          }
        }
        return;
      }

      // Backspace
      if (code === 127 || code === 8) {
        if (cursorPos > 0) {
          input = input.slice(0, cursorPos - 1) + input.slice(cursorPos);
          cursorPos--;
          redrawLine();
        }
        return;
      }

      // Arrow keys (escape sequences)
      if (key === '\u001b[D') {
        // Left arrow
        if (cursorPos > 0) {
          cursorPos--;
          redrawLine();
        }
        return;
      }
      if (key === '\u001b[C') {
        // Right arrow
        if (cursorPos < input.length) {
          cursorPos++;
          redrawLine();
        }
        return;
      }

      // Ignore other escape sequences
      if (key.startsWith('\u001b')) {
        return;
      }

      // Regular character - insert at cursor position
      if (code >= 32 && code < 127) {
        input = input.slice(0, cursorPos) + key + input.slice(cursorPos);
        cursorPos++;
        redrawLine();
      }
    });
  });
}
