import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';

// Create mock stream class
class MockStdout extends EventEmitter {
  pipe() { return this; }
}

// Create mock spawn process (simulates child_process.ChildProcess)
function createMockSpawnProcess(outputLines: string[] = []) {
  const stdout = new MockStdout();
  const stderr = new MockStdout();
  const mockProcess = new EventEmitter() as EventEmitter & {
    stdout: MockStdout;
    stderr: MockStdout;
    kill: ReturnType<typeof vi.fn>;
  };
  mockProcess.stdout = stdout;
  mockProcess.stderr = stderr;
  mockProcess.kill = vi.fn();

  // Simulate async streaming and exit
  setTimeout(() => {
    outputLines.forEach((line, i) => {
      setTimeout(() => stdout.emit('data', Buffer.from(line + '\n')), i * 10);
    });
    setTimeout(() => {
      mockProcess.emit('exit', 0);
    }, outputLines.length * 10 + 50);
  }, 0);

  return mockProcess;
}

// Create mock for execa (still used for adversarial validation)
function createMockExecaProcess(outputLines: string[] = []) {
  const stdout = new MockStdout();
  const mockProcess = {
    stdout,
    stderr: new MockStdout(),
    kill: vi.fn(),
    then: (resolve: any) => {
      setTimeout(() => {
        outputLines.forEach((line, i) => {
          setTimeout(() => stdout.emit('data', Buffer.from(line + '\n')), i * 10);
        });
        setTimeout(() => {
          stdout.emit('end');
          resolve({ exitCode: 0 });
        }, outputLines.length * 10 + 50);
      }, 0);
      return mockProcess;
    },
    catch: () => mockProcess,
  };
  return mockProcess;
}

vi.mock('child_process', () => ({
  spawn: vi.fn(),
}));

vi.mock('execa', () => ({
  execa: vi.fn(),
}));

vi.mock('fs', () => ({
  existsSync: vi.fn(),
  readFileSync: vi.fn(),
}));

vi.mock('../../../src/providers/detect', () => ({
  isProviderAvailable: vi.fn(),
  getProviderCommand: vi.fn().mockReturnValue('claude'),
}));

import { spawn } from 'child_process';
import { execa } from 'execa';
import { existsSync, readFileSync } from 'fs';
import { ClaudeCodeProvider } from '../../../src/providers/adapters/claude-code';
import { isProviderAvailable, getProviderCommand } from '../../../src/providers/detect';
import { CodebaseUnderstanding } from '../../../src/types';

describe('providers/adapters/claude-code', () => {
  let provider: ClaudeCodeProvider;

  const mockUnderstanding: CodebaseUnderstanding = {
    version: '1',
    generatedAt: '2024-01-01T00:00:00Z',
    summary: {
      type: 'api',
      framework: 'express',
      language: 'typescript',
      description: 'Test API',
    },
    features: [],
    contracts: [],
    dependencies: {},
    structure: {
      totalFiles: 10,
      totalLines: 1000,
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getProviderCommand).mockReturnValue('claude');
    provider = new ClaudeCodeProvider();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('constructor', () => {
    it('should create an instance', () => {
      expect(provider).toBeDefined();
    });

    it('should have name claude-code', () => {
      expect(provider.name).toBe('claude-code');
    });
  });

  describe('detect', () => {
    it('should return true when claude CLI is available', async () => {
      vi.mocked(isProviderAvailable).mockResolvedValue(true);

      const result = await provider.detect();

      expect(result).toBe(true);
      expect(isProviderAvailable).toHaveBeenCalledWith('claude-code');
    });

    it('should return false when claude CLI is not available', async () => {
      vi.mocked(isProviderAvailable).mockResolvedValue(false);

      const result = await provider.detect();

      expect(result).toBe(false);
    });
  });

  describe('isAvailable', () => {
    it('should return true when claude CLI is available', async () => {
      vi.mocked(isProviderAvailable).mockResolvedValue(true);

      const result = await provider.isAvailable();

      expect(result).toBe(true);
    });

    it('should return false when claude CLI is not available', async () => {
      vi.mocked(isProviderAvailable).mockResolvedValue(false);

      const result = await provider.isAvailable();

      expect(result).toBe(false);
    });
  });

  describe('analyze', () => {
    it('should return empty array for empty file list', async () => {
      const bugs = await provider.analyze({
        files: [],
        understanding: mockUnderstanding,
        config: {} as any,
        staticAnalysisResults: [],
      });

      expect(bugs).toEqual([]);
    });

    it('should analyze files and return bugs via streaming', async () => {
      const bugJson = JSON.stringify({
        file: 'src/test.ts',
        line: 10,
        title: 'Null dereference',
        description: 'Accessing property on null',
        severity: 'high',
        category: 'null-reference',
        codePath: [{ step: 1, file: 'src/test.ts', line: 10, code: 'x.foo', explanation: 'x may be null' }],
        evidence: ['No null check'],
      });

      const mockProcess = createMockSpawnProcess([
        '###SCANNING:src/test.ts',
        `###BUG:${bugJson}`,
        '###COMPLETE',
      ]);

      vi.mocked(spawn).mockReturnValue(mockProcess as any);

      const bugs = await provider.analyze({
        files: ['/project/src/test.ts'],
        understanding: mockUnderstanding,
        config: {} as any,
        staticAnalysisResults: [],
      });

      expect(bugs.length).toBe(1);
      expect(bugs[0].title).toBe('Null dereference');
      expect(bugs[0].severity).toBe('high');
      expect(bugs[0].category).toBe('null-reference');
    });

    it('should handle streaming with no bugs found', async () => {
      const mockProcess = createMockSpawnProcess([
        '###SCANNING:src/test.ts',
        '###SCANNING:src/utils.ts',
        '###COMPLETE',
      ]);

      vi.mocked(spawn).mockReturnValue(mockProcess as any);

      const bugs = await provider.analyze({
        files: ['/project/src/test.ts'],
        understanding: mockUnderstanding,
        config: {} as any,
        staticAnalysisResults: [],
      });

      expect(bugs).toEqual([]);
    });

    it('should handle multiple bugs in stream', async () => {
      const bug1 = JSON.stringify({ file: 'test.ts', line: 1, title: 'Bug 1', severity: 'high', category: 'logic-error' });
      const bug2 = JSON.stringify({ file: 'test.ts', line: 2, title: 'Bug 2', severity: 'medium', category: 'null-reference' });

      const mockProcess = createMockSpawnProcess([
        '###SCANNING:test.ts',
        `###BUG:${bug1}`,
        `###BUG:${bug2}`,
        '###COMPLETE',
      ]);

      vi.mocked(spawn).mockReturnValue(mockProcess as any);

      const bugs = await provider.analyze({
        files: ['/project/test.ts'],
        understanding: mockUnderstanding,
        config: {} as any,
        staticAnalysisResults: [],
      });

      expect(bugs.length).toBe(2);
      expect(bugs[0].title).toBe('Bug 1');
      expect(bugs[1].title).toBe('Bug 2');
    });

    it('should report progress via callback', async () => {
      const mockProcess = createMockSpawnProcess([
        '###SCANNING:src/api.ts',
        '###COMPLETE',
      ]);

      vi.mocked(spawn).mockReturnValue(mockProcess as any);

      const progressMessages: string[] = [];
      provider.setProgressCallback((msg) => progressMessages.push(msg));

      await provider.analyze({
        files: ['/project/src/api.ts'],
        understanding: mockUnderstanding,
        config: {} as any,
        staticAnalysisResults: [],
      });

      expect(progressMessages).toContain('Scanning: src/api.ts');
    });

    it('should call spawn with correct arguments (no unsafe flag by default)', async () => {
      const mockProcess = createMockSpawnProcess(['###COMPLETE']);
      vi.mocked(spawn).mockReturnValue(mockProcess as any);

      await provider.analyze({
        files: ['/project/src/test.ts'],
        understanding: mockUnderstanding,
        config: {} as any,
        staticAnalysisResults: [],
      });

      expect(spawn).toHaveBeenCalledWith(
        'claude',
        expect.arrayContaining(['--verbose', '-p']),
        expect.objectContaining({ env: expect.any(Object) })
      );
      // Should NOT contain the unsafe flag by default
      const callArgs = vi.mocked(spawn).mock.calls[0][1] as string[];
      expect(callArgs).not.toContain('--allowedTools');
    });

    it('should include --allowedTools when unsafe mode is enabled', async () => {
      const mockProcess = createMockSpawnProcess(['###COMPLETE']);
      vi.mocked(spawn).mockReturnValue(mockProcess as any);

      provider.setUnsafeMode(true);

      await provider.analyze({
        files: ['/project/src/test.ts'],
        understanding: mockUnderstanding,
        config: {} as any,
        staticAnalysisResults: [],
      });

      const callArgs = vi.mocked(spawn).mock.calls[0][1] as string[];
      expect(callArgs).toContain('--allowedTools');
    });
  });

  describe('adversarialValidate', () => {
    const mockBug = {
      id: 'WR-001',
      title: 'Null dereference',
      description: 'x may be null',
      file: '/project/src/test.ts',
      line: 10,
      severity: 'high' as const,
      category: 'null-reference' as const,
      confidence: {
        overall: 'medium' as const,
        codePathValidity: 0.8,
        reachability: 0.8,
        intentViolation: false,
        staticToolSignal: false,
        adversarialSurvived: false,
      },
      codePath: [{ step: 1, file: '/project/src/test.ts', line: 10, code: 'x.foo', explanation: 'x may be null' }],
      evidence: ['No null check'],
      createdAt: '2024-01-01T00:00:00Z',
    };

    it('should return survived true when bug cannot be disproved', async () => {
      vi.mocked(existsSync).mockReturnValue(true);
      vi.mocked(readFileSync).mockReturnValue('const x = null; x.foo;');
      vi.mocked(execa).mockResolvedValue({
        stdout: JSON.stringify({
          survived: true,
          counterArguments: [],
          confidence: 'high',
        }),
      } as any);

      const result = await provider.adversarialValidate(mockBug, {
        files: [],
        understanding: mockUnderstanding,
        config: {} as any,
        staticAnalysisResults: [],
      });

      expect(result.survived).toBe(true);
    });

    it('should handle disproved bug', async () => {
      vi.mocked(existsSync).mockReturnValue(true);
      vi.mocked(readFileSync).mockReturnValue('if (x) { x.foo; }');
      vi.mocked(execa).mockResolvedValue({
        stdout: '{"survived": false, "counterArguments": ["There is a null check"], "confidence": "high"}',
      } as any);

      const result = await provider.adversarialValidate(mockBug, {
        files: [],
        understanding: mockUnderstanding,
        config: {} as any,
        staticAnalysisResults: [],
      });

      expect(result).toHaveProperty('survived');
      expect(result).toHaveProperty('counterArguments');
    });

    it('should return survived true on parse error (conservative)', async () => {
      vi.mocked(existsSync).mockReturnValue(true);
      vi.mocked(readFileSync).mockReturnValue('const x = 1;');
      vi.mocked(execa).mockResolvedValue({ stdout: 'not json' } as any);

      const result = await provider.adversarialValidate(mockBug, {
        files: [],
        understanding: mockUnderstanding,
        config: {} as any,
        staticAnalysisResults: [],
      });

      expect(result.survived).toBe(true);
      expect(result.counterArguments).toEqual([]);
    });

    it('should handle file not existing', async () => {
      vi.mocked(existsSync).mockReturnValue(false);
      vi.mocked(execa).mockResolvedValue({
        stdout: JSON.stringify({ survived: true, counterArguments: [], confidence: 'medium' }),
      } as any);

      const result = await provider.adversarialValidate(mockBug, {
        files: [],
        understanding: mockUnderstanding,
        config: {} as any,
        staticAnalysisResults: [],
      });

      expect(result.survived).toBe(true);
    });
  });

  describe('generateUnderstanding', () => {
    it('should generate understanding via streaming', async () => {
      const understandingJson = JSON.stringify({
        summary: { type: 'api', language: 'typescript', description: 'API' },
        features: [],
        contracts: [],
      });

      const mockProcess = createMockSpawnProcess([
        '###SCANNING:package.json',
        '###SCANNING:src/index.ts',
        `###UNDERSTANDING:${understandingJson}`,
        '###COMPLETE',
      ]);

      vi.mocked(spawn).mockReturnValue(mockProcess as any);

      const understanding = await provider.generateUnderstanding(['/project/src/index.ts']);

      // The understanding is generated - either parsed correctly or fallback
      expect(understanding).toBeDefined();
      expect(understanding.structure.totalFiles).toBe(1);
    });

    it('should handle parse errors gracefully', async () => {
      const mockProcess = createMockSpawnProcess([
        '###UNDERSTANDING:not valid json',
        '###COMPLETE',
      ]);

      vi.mocked(spawn).mockReturnValue(mockProcess as any);

      const understanding = await provider.generateUnderstanding(['/project/src/index.ts']);

      expect(understanding.summary.type).toBe('unknown');
      expect(understanding.summary.description).toContain('Failed to analyze');
    });

    it('should report progress during analysis', async () => {
      const understandingJson = JSON.stringify({
        summary: { type: 'app', language: 'typescript', description: 'App' },
        features: [],
        contracts: [],
      });

      const mockProcess = createMockSpawnProcess([
        '###SCANNING:src/index.ts',
        `###UNDERSTANDING:${understandingJson}`,
        '###COMPLETE',
      ]);

      vi.mocked(spawn).mockReturnValue(mockProcess as any);

      const progressMessages: string[] = [];
      provider.setProgressCallback((msg) => progressMessages.push(msg));

      await provider.generateUnderstanding(['/project/src/index.ts']);

      expect(progressMessages).toContain('Examining: src/index.ts');
    });

    it('should return structure with totalFiles', async () => {
      const understandingJson = JSON.stringify({
        summary: { type: 'app', language: 'typescript', description: 'App' },
        features: [],
        contracts: [],
      });

      const mockProcess = createMockSpawnProcess([
        `###UNDERSTANDING:${understandingJson}`,
        '###COMPLETE',
      ]);

      vi.mocked(spawn).mockReturnValue(mockProcess as any);

      const understanding = await provider.generateUnderstanding([
        '/project/src/a.ts',
        '/project/src/b.ts',
      ]);

      expect(understanding.structure.totalFiles).toBe(2);
    });
  });

  describe('cancel', () => {
    it('should kill the current process', async () => {
      const mockProcess = createMockSpawnProcess(['###COMPLETE']);

      vi.mocked(spawn).mockReturnValue(mockProcess as any);

      // Start analysis (don't await)
      const analysisPromise = provider.analyze({
        files: ['/project/src/test.ts'],
        understanding: mockUnderstanding,
        config: {} as any,
        staticAnalysisResults: [],
      });

      // Cancel immediately
      provider.cancel();

      // Wait for analysis to complete
      await analysisPromise;

      expect(mockProcess.kill).toHaveBeenCalled();
    });
  });

  describe('callbacks', () => {
    it('should call bug found callback when bug is found', async () => {
      const bugJson = JSON.stringify({
        file: 'test.ts',
        line: 1,
        title: 'Test Bug',
        severity: 'high',
        category: 'logic-error',
      });

      const mockProcess = createMockSpawnProcess([
        `###BUG:${bugJson}`,
        '###COMPLETE',
      ]);

      vi.mocked(spawn).mockReturnValue(mockProcess as any);

      const foundBugs: any[] = [];
      provider.setBugFoundCallback((bug) => foundBugs.push(bug));

      await provider.analyze({
        files: ['/project/test.ts'],
        understanding: mockUnderstanding,
        config: {} as any,
        staticAnalysisResults: [],
      });

      expect(foundBugs.length).toBe(1);
      expect(foundBugs[0].title).toBe('Test Bug');
    });
  });
});
