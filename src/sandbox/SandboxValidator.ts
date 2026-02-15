/**
 * Sandbox Integration
 * Pre-execution validation and runtime constraint enforcement
 */

import logger from '../utils/logger.js';

export interface ExecutionContext {
    command: string;
    args: string[];
    environment: Record<string, string>;
    workingDirectory: string;
    requestedCapabilities: string[];
    agentMetadata: {
        name: string;
        version: string;
        source: string;
    };
}

export interface ValidationResult {
    allowed: boolean;
    riskScore: number;
    violations: PolicyViolation[];
    recommendations: string[];
    constraints?: ExecutionConstraints | undefined;
}

export interface PolicyViolation {
    type: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    description: string;
    evidence?: any;
}

export interface ExecutionConstraints {
    timeLimit: number; // milliseconds
    resources: {
        maxCpu: number; // percentage
        maxMemory: number; // MB
        maxDiskRead: number; // MB
        maxDiskWrite: number; // MB
    };
    network: {
        allowed: boolean;
        whitelist?: string[];
        blacklist?: string[];
    };
    fileSystem: {
        readOnly: string[];
        readWrite: string[];
        forbidden: string[];
    };
}

export class SandboxValidator {
    async validateExecution(context: ExecutionContext): Promise<ValidationResult> {
        logger.info(`Validating execution: ${context.command}`);

        const violations: PolicyViolation[] = [];

        // Check dangerous command patterns
        violations.push(...this.checkDangerousPatterns(context));

        // Check capability combinations
        violations.push(...this.checkCapabilities(context));

        // Check environment variables
        violations.push(...this.checkEnvironment(context));

        const riskScore = this.calculateRiskScore(violations);
        const allowed = violations.every(v => v.severity !== 'CRITICAL') && riskScore < 70;

        return {
            allowed,
            riskScore,
            violations,
            recommendations: this.generateRecommendations(context, violations),
            constraints: allowed ? this.generateConstraints(context) : undefined
        };
    }

    private checkDangerousPatterns(context: ExecutionContext): PolicyViolation[] {
        const violations: PolicyViolation[] = [];
        const fullCommand = `${context.command} ${context.args.join(' ')}`;

        const dangerousPatterns = [
            { pattern: /rm\s+-rf\s+\//, desc: 'Recursive delete from root' },
            { pattern: /curl.*\|\s*sh/, desc: 'Piping downloaded content to shell' },
            { pattern: /eval\s*\$\(/, desc: 'Eval with command substitution' },
            { pattern: /base64\s+-d.*\|\s*bash/, desc: 'Decoding and executing base64' }
        ];

        for (const { pattern, desc } of dangerousPatterns) {
            if (pattern.test(fullCommand)) {
                violations.push({
                    type: 'dangerous_command',
                    severity: 'CRITICAL',
                    description: `Dangerous command pattern: ${desc}`,
                    evidence: { command: fullCommand }
                });
            }
        }

        return violations;
    }

    private checkCapabilities(context: ExecutionContext): PolicyViolation[] {
        const violations: PolicyViolation[] = [];

        const dangerousCombos = [
            { caps: ['network:outbound', 'file:write', 'process:spawn'], severity: 'HIGH' as const },
            { caps: ['shell:execute', 'network:outbound'], severity: 'HIGH' as const },
            { caps: ['clipboard:read', 'network:outbound'], severity: 'MEDIUM' as const }
        ];

        for (const combo of dangerousCombos) {
            if (combo.caps.every(c => context.requestedCapabilities.includes(c))) {
                violations.push({
                    type: 'dangerous_capability_combo',
                    severity: combo.severity,
                    description: `Dangerous capability combination: ${combo.caps.join(', ')}`,
                    evidence: { capabilities: combo.caps }
                });
            }
        }

        return violations;
    }

    private checkEnvironment(context: ExecutionContext): PolicyViolation[] {
        const violations: PolicyViolation[] = [];

        // Check for exposed credentials in environment
        const sensitiveKeys = Object.keys(context.environment).filter(key =>
            key.includes('KEY') ||
            key.includes('SECRET') ||
            key.includes('TOKEN') ||
            key.includes('PASSWORD')
        );

        if (sensitiveKeys.length > 0) {
            violations.push({
                type: 'sensitive_env_vars',
                severity: 'MEDIUM',
                description: `${sensitiveKeys.length} sensitive environment variables exposed`,
                evidence: { keys: sensitiveKeys }
            });
        }

        return violations;
    }

    private calculateRiskScore(violations: PolicyViolation[]): number {
        let score = 0;
        for (const v of violations) {
            score += v.severity === 'CRITICAL' ? 40 : v.severity === 'HIGH' ? 25 : v.severity === 'MEDIUM' ? 15 : 5;
        }
        return Math.min(100, score);
    }

    private generateRecommendations(context: ExecutionContext, violations: PolicyViolation[]): string[] {
        const recommendations: string[] = [];

        if (violations.some(v => v.type === 'dangerous_command')) {
            recommendations.push('Review command for security implications before execution');
        }

        if (violations.some(v => v.type === 'dangerous_capability_combo')) {
            recommendations.push('Reduce requested capabilities to minimum necessary');
        }

        if (context.requestedCapabilities.length > 5) {
            recommendations.push('Consider splitting into smaller, more focused agents');
        }

        return recommendations;
    }

    private generateConstraints(context: ExecutionContext): ExecutionConstraints {
        return {
            timeLimit: 60000, // 1 minute
            resources: {
                maxCpu: 80,
                maxMemory: 512,
                maxDiskRead: 100,
                maxDiskWrite: 50
            },
            network: {
                allowed: context.requestedCapabilities.includes('network:outbound'),
                whitelist: [],
                blacklist: ['localhost', '127.0.0.1', '0.0.0.0']
            },
            fileSystem: {
                readOnly: ['/etc', '/usr', '/bin'],
                readWrite: [context.workingDirectory],
                forbidden: ['/root', '/.ssh', '/.aws']
            }
        };
    }
}
