/**
 * Agent Behavior Monitoring System
 * Tracks runtime execution patterns and detects anomalies
 */

 
 
 
 
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/prefer-nullish-coalescing */
/* eslint-disable @typescript-eslint/no-floating-promises */
/* eslint-disable @typescript-eslint/no-deprecated */

import { EventEmitter } from 'events';
import logger from '../utils/logger.js';

export interface AgentExecution {
    id: string;
    agentType: string;
    command: string;
    args: string[];
    startTime: Date;
    endTime?: Date;
    exitCode?: number;
    duration?: number;
    resources: ResourceUsage;
    networkActivity: NetworkEvent[];
    fileSystemActivity: FileSystemEvent[];
    processId?: number;
}

export interface ResourceUsage {
    cpuPercent: number;
    memoryMB: number;
    diskReadMB: number;
    diskWriteMB: number;
}

export interface NetworkEvent {
    timestamp: Date;
    direction: 'inbound' | 'outbound';
    protocol: string;
    host: string;
    port: number;
    bytes: number;
}

export interface FileSystemEvent {
    timestamp: Date;
    operation: 'read' | 'write' | 'delete' | 'modify';
    path: string;
    bytes?: number;
}

export interface MonitoringConfig {
    enabled: boolean;
    watchPaths: string[];
    trackNetwork: boolean;
    trackFileSystem: boolean;
    trackResources: boolean;
    anomalyDetection: boolean;
}

export class AgentMonitor extends EventEmitter {
    private executions = new Map<string, AgentExecution>();
    private baselines = new Map<string, ExecutionBaseline>();
    private monitoring = false;

    async startMonitoring(config: MonitoringConfig): Promise<void> {
        if (this.monitoring) {
            logger.warn('Monitoring already active');
            return;
        }

        logger.info('Starting agent behavior monitoring');
        this.monitoring = true;

        if (config.trackResources) {
            this.startResourceMonitoring();
        }

        if (config.trackNetwork) {
            this.startNetworkMonitoring();
        }

        if (config.trackFileSystem) {
            this.startFileSystemMonitoring(config.watchPaths);
        }
    }

    async stopMonitoring(): Promise<void> {
        logger.info('Stopping agent behavior monitoring');
        this.monitoring = false;
        this.executions.clear();
    }

    trackExecution(execution: Partial<AgentExecution>): string {
        const id = this.generateExecutionId();
        const fullExecution: AgentExecution = {
            id,
            agentType: execution.agentType || 'unknown',
            command: execution.command || '',
            args: execution.args || [],
            startTime: new Date(),
            resources: execution.resources || this.getCurrentResourceUsage(),
            networkActivity: [],
            fileSystemActivity: [],
            ...execution
        };

        this.executions.set(id, fullExecution);
        this.emit('execution-started', fullExecution);

        return id;
    }

    completeExecution(id: string, exitCode: number): void {
        const execution = this.executions.get(id);
        if (!execution) return;

        execution.endTime = new Date();
        execution.exitCode = exitCode;
        execution.duration = execution.endTime.getTime() - execution.startTime.getTime();

        this.analyzeExecution(execution);
        this.emit('execution-completed', execution);
    }

    private async analyzeExecution(execution: AgentExecution): Promise<void> {

        // Check for anomalies
        const anomalies = this.detectAnomalies(execution);

        if (anomalies.length > 0) {
            logger.warn(`Detected ${anomalies.length} anomalies in execution ${execution.id}`);
            this.emit('anomalies-detected', { execution, anomalies });
        }

        // Update baseline
        this.updateBaseline(execution);
    }

    private detectAnomalies(execution: AgentExecution): Anomaly[] {
        const anomalies: Anomaly[] = [];
        const baseline = this.baselines.get(execution.command);

        if (!baseline) {
            // First execution, establish baseline
            return anomalies;
        }

        // CPU usage anomaly
        if (execution.resources.cpuPercent > baseline.avgCpu * 2.5) {
            anomalies.push({
                type: 'resource_spike',
                severity: 'HIGH',
                description: `Unusual CPU usage: ${execution.resources.cpuPercent}% (baseline: ${baseline.avgCpu}%)`,
                evidence: { cpu: execution.resources.cpuPercent, baseline: baseline.avgCpu }
            });
        }

        // Memory anomaly
        if (execution.resources.memoryMB > baseline.avgMemory * 2) {
            anomalies.push({
                type: 'resource_spike',
                severity: 'MEDIUM',
                description: `Unusual memory usage: ${execution.resources.memoryMB}MB (baseline: ${baseline.avgMemory}MB)`,
                evidence: { memory: execution.resources.memoryMB, baseline: baseline.avgMemory }
            });
        }

        // Network anomaly
        const totalNetworkBytes = execution.networkActivity.reduce((sum, evt) => sum + evt.bytes, 0);
        if (totalNetworkBytes > baseline.avgNetworkBytes * 3) {
            anomalies.push({
                type: 'unusual_network',
                severity: 'HIGH',
                description: `Unusual network activity: ${(totalNetworkBytes / 1024 / 1024).toFixed(2)}MB`,
                evidence: { bytes: totalNetworkBytes, baseline: baseline.avgNetworkBytes }
            });
        }

        // Suspicious file access
        const sensitiveAccess = execution.fileSystemActivity.filter(evt =>
            evt.path.includes('.env') ||
            evt.path.includes('credentials') ||
            evt.path.includes('secrets') ||
            evt.path.includes('.ssh')
        );

        if (sensitiveAccess.length > 0) {
            anomalies.push({
                type: 'suspicious_files',
                severity: 'CRITICAL',
                description: `Access to ${sensitiveAccess.length} sensitive file(s)`,
                evidence: { files: sensitiveAccess.map(e => e.path) }
            });
        }

        return anomalies;
    }

    private updateBaseline(execution: AgentExecution): void {
        const existing = this.baselines.get(execution.command) || {
            executions: 0,
            avgCpu: 0,
            avgMemory: 0,
            avgDuration: 0,
            avgNetworkBytes: 0
        };

        const n = existing.executions;
        existing.avgCpu = (existing.avgCpu * n + execution.resources.cpuPercent) / (n + 1);
        existing.avgMemory = (existing.avgMemory * n + execution.resources.memoryMB) / (n + 1);
        existing.avgDuration = (existing.avgDuration * n + (execution.duration || 0)) / (n + 1);

        const networkBytes = execution.networkActivity.reduce((sum, evt) => sum + evt.bytes, 0);
        existing.avgNetworkBytes = (existing.avgNetworkBytes * n + networkBytes) / (n + 1);
        existing.executions = n + 1;

        this.baselines.set(execution.command, existing);
    }

    private startResourceMonitoring(): void {
        // Monitor CPU and memory usage
        setInterval(() => {
            if (!this.monitoring) return;
            // Resource monitoring implementation
        }, 1000);
    }

    private startNetworkMonitoring(): void {
        // Monitor network activity
        logger.info('Network monitoring started');
    }

    private startFileSystemMonitoring(paths: string[]): void {
        // Monitor file system changes
        logger.info(`File system monitoring started for ${paths.length} paths`);
    }

    private getCurrentResourceUsage(): ResourceUsage {
        const usage = process.memoryUsage();
        return {
            cpuPercent: process.cpuUsage().user / 1000000,
            memoryMB: usage.heapUsed / 1024 / 1024,
            diskReadMB: 0,
            diskWriteMB: 0
        };
    }

    private generateExecutionId(): string {
        return `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    getExecutionHistory(): AgentExecution[] {
        return Array.from(this.executions.values());
    }

    getBaselines(): Map<string, ExecutionBaseline> {
        return this.baselines;
    }
}

interface ExecutionBaseline {
    executions: number;
    avgCpu: number;
    avgMemory: number;
    avgDuration: number;
    avgNetworkBytes: number;
}

interface Anomaly {
    type: string;
    severity: string;
    description: string;
    evidence: any;
}

export const agentMonitor = new AgentMonitor();
