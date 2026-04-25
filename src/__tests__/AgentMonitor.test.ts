/**
 * AgentMonitor Tests
 * Tests for the AgentMonitor class in src/monitoring/AgentMonitor.ts
 */

import { AgentMonitor, agentMonitor } from '../monitoring/AgentMonitor.js';
import type { MonitoringConfig } from '../monitoring/AgentMonitor.js';

function makeConfig(overrides: Partial<MonitoringConfig> = {}): MonitoringConfig {
  return {
    enabled: true,
    watchPaths: [],
    trackNetwork: false,
    trackFileSystem: false,
    trackResources: false,
    anomalyDetection: true,
    ...overrides,
  };
}

describe('AgentMonitor', () => {
  let monitor: AgentMonitor;

  beforeEach(() => {
    monitor = new AgentMonitor();
  });

  afterEach(async () => {
    await monitor.stopMonitoring();
  });

  // -------------------------------------------------------------------------
  // startMonitoring / stopMonitoring
  // -------------------------------------------------------------------------

  describe('startMonitoring', () => {
    it('starts monitoring without error', async () => {
      await expect(monitor.startMonitoring(makeConfig())).resolves.toBeUndefined();
    });

    it('is idempotent – calling twice does not throw', async () => {
      await monitor.startMonitoring(makeConfig());
      await expect(monitor.startMonitoring(makeConfig())).resolves.toBeUndefined();
    });

    it('starts with trackResources=true', async () => {
      await expect(
        monitor.startMonitoring(makeConfig({ trackResources: true }))
      ).resolves.toBeUndefined();
    });

    it('starts with trackNetwork=true', async () => {
      await expect(
        monitor.startMonitoring(makeConfig({ trackNetwork: true }))
      ).resolves.toBeUndefined();
    });

    it('starts with trackFileSystem=true and watchPaths', async () => {
      await expect(
        monitor.startMonitoring(makeConfig({ trackFileSystem: true, watchPaths: ['/tmp'] }))
      ).resolves.toBeUndefined();
    });
  });

  describe('stopMonitoring', () => {
    it('stops without error even when not started', async () => {
      await expect(monitor.stopMonitoring()).resolves.toBeUndefined();
    });

    it('clears execution history on stop', async () => {
      await monitor.startMonitoring(makeConfig());
      monitor.trackExecution({ command: 'test-cmd', agentType: 'test' });
      expect(monitor.getExecutionHistory()).toHaveLength(1);
      await monitor.stopMonitoring();
      expect(monitor.getExecutionHistory()).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // trackExecution
  // -------------------------------------------------------------------------

  describe('trackExecution', () => {
    it('returns an execution id string', () => {
      const id = monitor.trackExecution({ command: 'ls', agentType: 'test' });
      expect(typeof id).toBe('string');
      expect(id).toMatch(/^exec_/);
    });

    it('stores execution in history', () => {
      monitor.trackExecution({ command: 'ls', agentType: 'test' });
      expect(monitor.getExecutionHistory()).toHaveLength(1);
    });

    it('fills in defaults for missing fields', () => {
      const id = monitor.trackExecution({});
      const history = monitor.getExecutionHistory();
      const exec = history.find(e => e.id === id);
      expect(exec).toBeDefined();
      expect(exec?.agentType).toBe('unknown');
      expect(exec?.command).toBe('');
      expect(exec?.args).toEqual([]);
      expect(exec?.networkActivity).toEqual([]);
      expect(exec?.fileSystemActivity).toEqual([]);
    });

    it('emits execution-started event', () => {
      const listener = jest.fn();
      monitor.on('execution-started', listener);
      monitor.trackExecution({ command: 'echo', agentType: 'test' });
      expect(listener).toHaveBeenCalledTimes(1);
      expect(listener.mock.calls[0][0]).toMatchObject({ command: 'echo' });
    });

    it('supports multiple executions', () => {
      monitor.trackExecution({ command: 'cmd1' });
      monitor.trackExecution({ command: 'cmd2' });
      monitor.trackExecution({ command: 'cmd3' });
      expect(monitor.getExecutionHistory()).toHaveLength(3);
    });
  });

  // -------------------------------------------------------------------------
  // completeExecution
  // -------------------------------------------------------------------------

  describe('completeExecution', () => {
    it('does nothing if id is unknown', () => {
      expect(() => monitor.completeExecution('nonexistent-id', 0)).not.toThrow();
    });

    it('sets endTime, exitCode, and duration on known execution', () => {
      const id = monitor.trackExecution({ command: 'sleep', agentType: 'test' });
      monitor.completeExecution(id, 0);
      const exec = monitor.getExecutionHistory().find(e => e.id === id);
      expect(exec?.exitCode).toBe(0);
      expect(exec?.endTime).toBeInstanceOf(Date);
      expect(typeof exec?.duration).toBe('number');
      expect(exec!.duration!).toBeGreaterThanOrEqual(0);
    });

    it('emits execution-completed event', () => {
      const listener = jest.fn();
      monitor.on('execution-completed', listener);
      const id = monitor.trackExecution({ command: 'test', agentType: 'test' });
      monitor.completeExecution(id, 1);
      expect(listener).toHaveBeenCalledTimes(1);
      expect(listener.mock.calls[0][0]).toMatchObject({ exitCode: 1 });
    });
  });

  // -------------------------------------------------------------------------
  // Baseline & anomaly detection
  // -------------------------------------------------------------------------

  describe('baseline updates', () => {
    it('starts with empty baselines', () => {
      expect(monitor.getBaselines().size).toBe(0);
    });

    it('builds baseline after completing an execution', () => {
      const id = monitor.trackExecution({ command: 'my-cmd', agentType: 'test' });
      monitor.completeExecution(id, 0);
      expect(monitor.getBaselines().has('my-cmd')).toBe(true);
    });

    it('updates baseline across multiple executions', () => {
      for (let i = 0; i < 3; i++) {
        const id = monitor.trackExecution({ command: 'repeat-cmd', agentType: 'test' });
        monitor.completeExecution(id, 0);
      }
      const baseline = monitor.getBaselines().get('repeat-cmd');
      expect(baseline?.executions).toBe(3);
    });
  });

  describe('anomaly detection', () => {
    it('emits anomalies-detected on CPU spike', () => {
      const anomalyListener = jest.fn();
      monitor.on('anomalies-detected', anomalyListener);

      // Establish baseline with normal CPU usage
      const id1 = monitor.trackExecution({
        command: 'spike-cmd',
        agentType: 'test',
        resources: { cpuPercent: 10, memoryMB: 100, diskReadMB: 0, diskWriteMB: 0 },
      });
      monitor.completeExecution(id1, 0);

      // Now simulate a CPU spike (> 2.5x baseline)
      const id2 = monitor.trackExecution({
        command: 'spike-cmd',
        agentType: 'test',
        resources: { cpuPercent: 5000, memoryMB: 100, diskReadMB: 0, diskWriteMB: 0 },
      });
      monitor.completeExecution(id2, 0);

      expect(anomalyListener).toHaveBeenCalled();
      const call = anomalyListener.mock.calls[anomalyListener.mock.calls.length - 1][0] as {
        anomalies: { type: string }[];
      };
      expect(call.anomalies.some(a => a.type === 'resource_spike')).toBe(true);
    });

    it('emits anomalies-detected on memory spike', () => {
      const anomalyListener = jest.fn();
      monitor.on('anomalies-detected', anomalyListener);

      const id1 = monitor.trackExecution({
        command: 'mem-cmd',
        agentType: 'test',
        resources: { cpuPercent: 5, memoryMB: 50, diskReadMB: 0, diskWriteMB: 0 },
      });
      monitor.completeExecution(id1, 0);

      // 2x spike
      const id2 = monitor.trackExecution({
        command: 'mem-cmd',
        agentType: 'test',
        resources: { cpuPercent: 5, memoryMB: 10000, diskReadMB: 0, diskWriteMB: 0 },
      });
      monitor.completeExecution(id2, 0);

      expect(anomalyListener).toHaveBeenCalled();
    });

    it('emits anomalies-detected for suspicious file access', () => {
      const anomalyListener = jest.fn();
      monitor.on('anomalies-detected', anomalyListener);

      // Establish baseline first
      const id1 = monitor.trackExecution({ command: 'file-cmd', agentType: 'test' });
      monitor.completeExecution(id1, 0);

      // Execution that accesses sensitive files
      const id2 = monitor.trackExecution({
        command: 'file-cmd',
        agentType: 'test',
        fileSystemActivity: [
          { timestamp: new Date(), operation: 'read', path: '/home/user/.env', bytes: 100 },
          { timestamp: new Date(), operation: 'read', path: '/home/user/.ssh/id_rsa', bytes: 200 },
        ],
      });
      monitor.completeExecution(id2, 0);

      expect(anomalyListener).toHaveBeenCalled();
      const lastCall = anomalyListener.mock.calls[anomalyListener.mock.calls.length - 1][0] as {
        anomalies: { type: string }[];
      };
      expect(lastCall.anomalies.some(a => a.type === 'suspicious_files')).toBe(true);
    });

    it('emits anomalies-detected for unusual network activity', () => {
      const anomalyListener = jest.fn();
      monitor.on('anomalies-detected', anomalyListener);

      // Establish baseline with minimal network
      const id1 = monitor.trackExecution({
        command: 'net-cmd',
        agentType: 'test',
        networkActivity: [{ timestamp: new Date(), direction: 'outbound', protocol: 'tcp', host: 'example.com', port: 80, bytes: 100 }],
      });
      monitor.completeExecution(id1, 0);

      // Big spike (> 3x)
      const id2 = monitor.trackExecution({
        command: 'net-cmd',
        agentType: 'test',
        networkActivity: [
          { timestamp: new Date(), direction: 'outbound', protocol: 'tcp', host: 'evil.com', port: 443, bytes: 1_000_000_000 },
        ],
      });
      monitor.completeExecution(id2, 0);

      expect(anomalyListener).toHaveBeenCalled();
      const lastCall = anomalyListener.mock.calls[anomalyListener.mock.calls.length - 1][0] as {
        anomalies: { type: string }[];
      };
      expect(lastCall.anomalies.some(a => a.type === 'unusual_network')).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Exported singleton
  // -------------------------------------------------------------------------

  describe('agentMonitor singleton', () => {
    it('is an instance of AgentMonitor', () => {
      expect(agentMonitor).toBeInstanceOf(AgentMonitor);
    });
  });
});
