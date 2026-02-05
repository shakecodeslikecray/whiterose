import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('execa', () => ({
  execa: vi.fn(),
}));

vi.mock('../../../src/providers/detect', () => ({
  isProviderAvailable: vi.fn(),
  getProviderCommand: vi.fn().mockReturnValue('opencode'),
}));

import { execa } from 'execa';
import { OpenCodeExecutor } from '../../../src/providers/executors/opencode';
import { isProviderAvailable, getProviderCommand } from '../../../src/providers/detect';

describe('providers/executors/opencode', () => {
  let executor: OpenCodeExecutor;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getProviderCommand).mockReturnValue('opencode');
    executor = new OpenCodeExecutor();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('constructor', () => {
    it('should create an instance', () => {
      expect(executor).toBeDefined();
    });

    it('should have name opencode', () => {
      expect(executor.name).toBe('opencode');
    });
  });

  describe('isAvailable', () => {
    it('should return true when opencode CLI is available', async () => {
      vi.mocked(isProviderAvailable).mockResolvedValue(true);

      const result = await executor.isAvailable();

      expect(result).toBe(true);
      expect(isProviderAvailable).toHaveBeenCalledWith('opencode');
    });

    it('should return false when opencode CLI is not available', async () => {
      vi.mocked(isProviderAvailable).mockResolvedValue(false);

      const result = await executor.isAvailable();

      expect(result).toBe(false);
    });
  });

  describe('runPrompt', () => {
    it('should execute opencode run with prompt', async () => {
      vi.mocked(execa).mockResolvedValue({
        stdout: 'analysis result',
        stderr: '',
      } as any);

      const result = await executor.runPrompt('analyze this code', { cwd: '/project' });

      expect(execa).toHaveBeenCalledWith(
        'opencode',
        ['run', 'analyze this code'],
        expect.objectContaining({
          cwd: '/project',
          timeout: 300000,
          env: expect.objectContaining({ NO_COLOR: '1' }),
          reject: false,
        })
      );
      expect(result.output).toBe('analysis result');
      expect(result.error).toBeUndefined();
    });

    it('should use custom timeout when provided', async () => {
      vi.mocked(execa).mockResolvedValue({
        stdout: 'result',
        stderr: '',
      } as any);

      await executor.runPrompt('prompt', { cwd: '/project', timeout: 60000 });

      expect(execa).toHaveBeenCalledWith(
        'opencode',
        ['run', 'prompt'],
        expect.objectContaining({ timeout: 60000 })
      );
    });

    it('should return stderr as error when present alongside stdout', async () => {
      vi.mocked(execa).mockResolvedValue({
        stdout: 'some output',
        stderr: 'some warning',
      } as any);

      const result = await executor.runPrompt('prompt', { cwd: '/project' });

      expect(result.output).toBe('some output');
      expect(result.error).toBe('some warning');
    });

    it('should throw on rate limit error', async () => {
      vi.mocked(execa).mockResolvedValue({
        stdout: '',
        stderr: 'Error 429: rate limit exceeded',
      } as any);

      await expect(executor.runPrompt('prompt', { cwd: '/project' }))
        .rejects.toThrow('OpenCode API rate limit reached');
    });

    it('should throw on authentication error (401)', async () => {
      vi.mocked(execa).mockResolvedValue({
        stdout: '',
        stderr: 'Error 401 unauthorized',
      } as any);

      await expect(executor.runPrompt('prompt', { cwd: '/project' }))
        .rejects.toThrow('OpenCode API authentication failed');
    });

    it('should throw on authentication error (403)', async () => {
      vi.mocked(execa).mockResolvedValue({
        stdout: '',
        stderr: '403 Forbidden',
      } as any);

      await expect(executor.runPrompt('prompt', { cwd: '/project' }))
        .rejects.toThrow('OpenCode API authentication failed');
    });

    it('should throw on generic error when no stdout', async () => {
      vi.mocked(execa).mockResolvedValue({
        stdout: '',
        stderr: 'Error: something went wrong with a long message',
      } as any);

      await expect(executor.runPrompt('prompt', { cwd: '/project' }))
        .rejects.toThrow('OpenCode error:');
    });

    it('should not throw on stderr error when stdout has content', async () => {
      vi.mocked(execa).mockResolvedValue({
        stdout: 'valid output',
        stderr: 'Error: non-fatal warning',
      } as any);

      const result = await executor.runPrompt('prompt', { cwd: '/project' });

      expect(result.output).toBe('valid output');
      expect(result.error).toBe('Error: non-fatal warning');
    });

    it('should throw install message on ENOENT', async () => {
      vi.mocked(execa).mockRejectedValue(new Error('spawn opencode ENOENT'));

      await expect(executor.runPrompt('prompt', { cwd: '/project' }))
        .rejects.toThrow('OpenCode CLI not found. Install: curl -fsSL https://opencode.ai/install | bash');
    });

    it('should re-throw other errors', async () => {
      vi.mocked(execa).mockRejectedValue(new Error('timeout exceeded'));

      await expect(executor.runPrompt('prompt', { cwd: '/project' }))
        .rejects.toThrow('timeout exceeded');
    });

    it('should return empty string output when stdout is empty', async () => {
      vi.mocked(execa).mockResolvedValue({
        stdout: '',
        stderr: '',
      } as any);

      const result = await executor.runPrompt('prompt', { cwd: '/project' });

      expect(result.output).toBe('');
      expect(result.error).toBeUndefined();
    });
  });
});
