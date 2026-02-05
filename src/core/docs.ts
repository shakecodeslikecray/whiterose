/**
 * Documentation Parser - Layer 0
 *
 * Reads existing documentation from the codebase and extracts
 * relevant information for understanding intent.
 */

import { existsSync, readFileSync } from 'fs';
import { join, basename } from 'path';
import fg from 'fast-glob';

export interface ExistingDocs {
  readme: string | null;
  contributing: string | null;
  apiDocs: string[];
  changelog: string | null;
  packageJson: Record<string, unknown> | null;
  tsconfig: Record<string, unknown> | null;
  envExample: string | null;
  otherDocs: Array<{ name: string; content: string }>;
}

export interface ExtractedIntent {
  projectName: string;
  description: string;
  features: string[];
  techStack: string[];
  conventions: string[];
  apiEndpoints: string[];
  envVariables: string[];
  scripts: Record<string, string>;
}

/**
 * Read all existing documentation from a codebase
 */
export async function readExistingDocs(cwd: string): Promise<ExistingDocs> {
  const docs: ExistingDocs = {
    readme: null,
    contributing: null,
    apiDocs: [],
    changelog: null,
    packageJson: null,
    tsconfig: null,
    envExample: null,
    otherDocs: [],
  };

  // Read README
  for (const name of ['README.md', 'readme.md', 'README', 'Readme.md']) {
    const path = join(cwd, name);
    if (existsSync(path)) {
      docs.readme = readFileSync(path, 'utf-8');
      break;
    }
  }

  // Read CONTRIBUTING
  for (const name of ['CONTRIBUTING.md', 'contributing.md', 'CONTRIBUTING']) {
    const path = join(cwd, name);
    if (existsSync(path)) {
      docs.contributing = readFileSync(path, 'utf-8');
      break;
    }
  }

  // Read CHANGELOG
  for (const name of ['CHANGELOG.md', 'changelog.md', 'CHANGELOG', 'HISTORY.md']) {
    const path = join(cwd, name);
    if (existsSync(path)) {
      docs.changelog = readFileSync(path, 'utf-8');
      break;
    }
  }

  // Read package.json
  const packageJsonPath = join(cwd, 'package.json');
  if (existsSync(packageJsonPath)) {
    try {
      docs.packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
    } catch {
      // Ignore parse errors
    }
  }

  // Read tsconfig.json
  const tsconfigPath = join(cwd, 'tsconfig.json');
  if (existsSync(tsconfigPath)) {
    try {
      docs.tsconfig = JSON.parse(readFileSync(tsconfigPath, 'utf-8'));
    } catch {
      // Ignore parse errors
    }
  }

  // Read .env.example
  for (const name of ['.env.example', '.env.sample', '.env.template']) {
    const path = join(cwd, name);
    if (existsSync(path)) {
      docs.envExample = readFileSync(path, 'utf-8');
      break;
    }
  }

  // Find and read API docs
  const apiDocPaths = await fg(['docs/**/*.md', 'documentation/**/*.md', 'api/**/*.md'], {
    cwd,
    absolute: true,
    ignore: ['**/node_modules/**'],
  });

  for (const path of apiDocPaths.slice(0, 10)) {
    try {
      docs.apiDocs.push(readFileSync(path, 'utf-8'));
    } catch {
      // Skip unreadable files
    }
  }

  // Find other markdown docs
  const otherDocPaths = await fg(['*.md', 'docs/*.md'], {
    cwd,
    absolute: true,
    ignore: ['**/node_modules/**', 'README.md', 'CONTRIBUTING.md', 'CHANGELOG.md'],
  });

  for (const path of otherDocPaths.slice(0, 5)) {
    try {
      docs.otherDocs.push({
        name: basename(path),
        content: readFileSync(path, 'utf-8'),
      });
    } catch {
      // Skip unreadable files
    }
  }

  return docs;
}

/**
 * Extract structured intent from existing documentation
 */
export function extractIntentFromDocs(docs: ExistingDocs): ExtractedIntent {
  const intent: ExtractedIntent = {
    projectName: '',
    description: '',
    features: [],
    techStack: [],
    conventions: [],
    apiEndpoints: [],
    envVariables: [],
    scripts: {},
  };

  // Extract from package.json
  if (docs.packageJson) {
    intent.projectName = (docs.packageJson as any).name || '';
    intent.description = (docs.packageJson as any).description || '';
    intent.scripts = (docs.packageJson as any).scripts || {};

    // Extract tech stack from dependencies
    const deps = {
      ...(docs.packageJson as any).dependencies,
      ...(docs.packageJson as any).devDependencies,
    };

    if (deps) {
      if (deps['next']) intent.techStack.push('Next.js');
      if (deps['react']) intent.techStack.push('React');
      if (deps['vue']) intent.techStack.push('Vue');
      if (deps['express']) intent.techStack.push('Express');
      if (deps['fastify']) intent.techStack.push('Fastify');
      if (deps['typescript']) intent.techStack.push('TypeScript');
      if (deps['prisma']) intent.techStack.push('Prisma');
      if (deps['mongoose']) intent.techStack.push('MongoDB/Mongoose');
      if (deps['pg'] || deps['postgres']) intent.techStack.push('PostgreSQL');
      if (deps['redis']) intent.techStack.push('Redis');
      if (deps['stripe']) intent.techStack.push('Stripe');
      if (deps['@auth/core'] || deps['next-auth']) intent.techStack.push('Auth.js');
    }
  }

  // Extract features from README
  if (docs.readme) {
    // Look for features section
    const featuresMatch = docs.readme.match(/##\s*Features?\s*\n([\s\S]*?)(?=\n##|\n---|$)/i);
    if (featuresMatch) {
      const featureLines = featuresMatch[1].split('\n')
        .filter(line => line.trim().startsWith('-') || line.trim().startsWith('*'))
        .map(line => line.replace(/^[-*]\s*/, '').trim())
        .filter(line => line.length > 0);
      intent.features.push(...featureLines.slice(0, 20));
    }
  }

  // Extract env variables
  if (docs.envExample) {
    const envLines = docs.envExample.split('\n')
      .filter(line => line.includes('=') && !line.startsWith('#'))
      .map(line => line.split('=')[0].trim())
      .filter(line => line.length > 0);
    intent.envVariables.push(...envLines);
  }

  // Extract API endpoints from docs
  for (const apiDoc of docs.apiDocs) {
    const endpointMatches = apiDoc.matchAll(/`(GET|POST|PUT|DELETE|PATCH)\s+([^`]+)`/g);
    for (const match of endpointMatches) {
      intent.apiEndpoints.push(`${match[1]} ${match[2]}`);
    }
  }

  // Extract conventions from CONTRIBUTING
  if (docs.contributing) {
    const conventionLines = docs.contributing.split('\n')
      .filter(line => line.trim().startsWith('-') || line.trim().startsWith('*'))
      .map(line => line.replace(/^[-*]\s*/, '').trim())
      .filter(line => line.length > 10 && line.length < 200)
      .slice(0, 10);
    intent.conventions.push(...conventionLines);
  }

  return intent;
}

/**
 * Build a documentation summary for the AI prompt
 */
export function buildDocsSummary(docs: ExistingDocs, extracted: ExtractedIntent): string {
  const parts: string[] = [];

  parts.push(`# Existing Documentation Summary\n`);

  if (extracted.projectName) {
    parts.push(`## Project: ${extracted.projectName}`);
    if (extracted.description) {
      parts.push(`\n${extracted.description}\n`);
    }
  }

  if (extracted.techStack.length > 0) {
    parts.push(`\n## Tech Stack`);
    parts.push(extracted.techStack.map(t => `- ${t}`).join('\n'));
  }

  if (extracted.features.length > 0) {
    parts.push(`\n## Features (from README)`);
    parts.push(extracted.features.map(f => `- ${f}`).join('\n'));
  }

  if (extracted.apiEndpoints.length > 0) {
    parts.push(`\n## API Endpoints`);
    parts.push(extracted.apiEndpoints.slice(0, 20).map(e => `- ${e}`).join('\n'));
  }

  if (extracted.envVariables.length > 0) {
    parts.push(`\n## Environment Variables`);
    parts.push(extracted.envVariables.map(v => `- ${v}`).join('\n'));
  }

  if (extracted.conventions.length > 0) {
    parts.push(`\n## Conventions (from CONTRIBUTING)`);
    parts.push(extracted.conventions.map(c => `- ${c}`).join('\n'));
  }

  if (Object.keys(extracted.scripts).length > 0) {
    parts.push(`\n## NPM Scripts`);
    for (const [name, cmd] of Object.entries(extracted.scripts).slice(0, 10)) {
      parts.push(`- \`npm run ${name}\`: ${cmd}`);
    }
  }

  // Include README excerpt if available
  if (docs.readme && docs.readme.length > 0) {
    const excerpt = docs.readme.slice(0, 2000);
    parts.push(`\n## README Excerpt\n\`\`\`\n${excerpt}\n\`\`\``);
  }

  return parts.join('\n');
}
