/**
 * Compliance Framework Integration
 * Maps findings to SOC2, ISO27001, GDPR requirements
 */

import type { ScanResult, Finding } from '../types.js';
import logger from '../utils/logger.js';

export interface ComplianceAssessment {
    framework: 'SOC2' | 'ISO27001' | 'GDPR';
    assessmentDate: Date;
    overallScore: number; // 0-100
    controlAssessments: ControlAssessment[];
    recommendations: string[];
    nonCompliantControls: string[];
}

export interface ControlAssessment {
    controlId: string;
    controlName: string;
    status: 'compliant' | 'partially_compliant' | 'non_compliant';
    score: number; // 0-100
    findings: Finding[];
    evidence: string[];
    recommendations: string[];
}

export class ComplianceMapper {
    async assessSOC2(scanResult: ScanResult): Promise<ComplianceAssessment> {
        logger.info('Performing SOC2 compliance assessment');

        const controls = this.getSOC2Controls();
        const assessments: ControlAssessment[] = [];

        for (const control of controls) {
            const assessment = this.assessControl(control, scanResult);
            assessments.push(assessment);
        }

        const overallScore = assessments.reduce((sum, a) => sum + a.score, 0) / assessments.length;
        const nonCompliant = assessments.filter(a => a.status !== 'compliant').map(a => a.controlId);

        return {
            framework: 'SOC2',
            assessmentDate: new Date(),
            overallScore: Math.round(overallScore),
            controlAssessments: assessments,
            recommendations: this.generateSOC2Recommendations(assessments),
            nonCompliantControls: nonCompliant
        };
    }

    async assessISO27001(scanResult: ScanResult): Promise<ComplianceAssessment> {
        logger.info('Performing ISO 27001 compliance assessment');

        const controls = this.getISO27001Controls();
        const assessments: ControlAssessment[] = [];

        for (const control of controls) {
            const assessment = this.assessControl(control, scanResult);
            assessments.push(assessment);
        }

        const overallScore = assessments.reduce((sum, a) => sum + a.score, 0) / assessments.length;
        const nonCompliant = assessments.filter(a => a.status !== 'compliant').map(a => a.controlId);

        return {
            framework: 'ISO27001',
            assessmentDate: new Date(),
            overallScore: Math.round(overallScore),
            controlAssessments: assessments,
            recommendations: this.generateISO27001Recommendations(assessments),
            nonCompliantControls: nonCompliant
        };
    }

    async assessGDPR(scanResult: ScanResult): Promise<ComplianceAssessment> {
        logger.info('Performing GDPR compliance assessment');

        const controls = this.getGDPRControls();
        const assessments: ControlAssessment[] = [];

        for (const control of controls) {
            const assessment = this.assessControl(control, scanResult);
            assessments.push(assessment);
        }

        const overallScore = assessments.reduce((sum, a) => sum + a.score, 0) / assessments.length;
        const nonCompliant = assessments.filter(a => a.status !== 'compliant').map(a => a.controlId);

        return {
            framework: 'GDPR',
            assessmentDate: new Date(),
            overallScore: Math.round(overallScore),
            controlAssessments: assessments,
            recommendations: this.generateGDPRRecommendations(assessments),
            nonCompliantControls: nonCompliant
        };
    }

    private assessControl(control: ComplianceControl, scanResult: ScanResult): ControlAssessment {
        const relevantFindings = scanResult.findings.filter(f =>
            control.relevantCategories.includes(f.category)
        );

        let score = 100;
        for (const finding of relevantFindings) {
            score -= finding.severity === 'CRITICAL' ? 30 : finding.severity === 'HIGH' ? 20 : 10;
        }
        score = Math.max(0, score);

        return {
            controlId: control.id,
            controlName: control.name,
            status: score >= 80 ? 'compliant' : score >= 60 ? 'partially_compliant' : 'non_compliant',
            score,
            findings: relevantFindings,
            evidence: this.collectEvidence(control, scanResult),
            recommendations: this.getControlRecommendations(control, relevantFindings)
        };
    }

    private getSOC2Controls(): ComplianceControl[] {
        return [
            {
                id: 'CC6.1',
                name: 'Logical and Physical Access Controls',
                relevantCategories: ['credentials', 'permissions', 'backdoors']
            },
            {
                id: 'CC6.7',
                name: 'System Monitoring',
                relevantCategories: ['exfiltration', 'injection', 'ai-specific']
            },
            {
                id: 'CC7.1',
                name: 'System Operations',
                relevantCategories: ['supply-chain', 'persistence']
            }
        ];
    }

    private getISO27001Controls(): ComplianceControl[] {
        return [
            {
                id: 'A.9.1',
                name: 'Access Control Policy',
                relevantCategories: ['credentials', 'permissions']
            },
            {
                id: 'A.12.2',
                name: 'Protection from Malware',
                relevantCategories: ['backdoors', 'obfuscation']
            },
            {
                id: 'A.14.2',
                name: 'Security in Development',
                relevantCategories: ['injection', 'ai-specific']
            }
        ];
    }

    private getGDPRControls(): ComplianceControl[] {
        return [
            {
                id: 'Art.32',
                name: 'Security of Processing',
                relevantCategories: ['credentials', 'exfiltration']
            },
            {
                id: 'Art.25',
                name: 'Data Protection by Design',
                relevantCategories: ['ai-specific', 'permissions']
            }
        ];
    }

    private collectEvidence(_control: ComplianceControl, scanResult: ScanResult): string[] {
        return [
            `Scanned ${scanResult.analyzedFiles} files`,
            `Found ${scanResult.findings.length} security issues`,
            `Risk score: ${scanResult.overallRiskScore}/100`
        ];
    }

    private getControlRecommendations(_control: ComplianceControl, findings: Finding[]): string[] {
        const recs: string[] = [];

        if (findings.some(f => f.category === 'credentials')) {
            recs.push('Implement secrets management solution');
            recs.push('Move credentials to environment variables or vault');
        }

        if (findings.some(f => f.category === 'exfiltration')) {
            recs.push('Review all network communication patterns');
            recs.push('Implement data loss prevention controls');
        }

        return recs;
    }

    private generateSOC2Recommendations(assessments: ControlAssessment[]): string[] {
        const recs: string[] = [];
        const nonCompliant = assessments.filter(a => a.status !== 'compliant');

        if (nonCompliant.length > 0) {
            recs.push(`Address ${nonCompliant.length} non-compliant control(s)`);
        }

        return recs;
    }

    private generateISO27001Recommendations(assessments: ControlAssessment[]): string[] {
        return this.generateSOC2Recommendations(assessments);
    }

    private generateGDPRRecommendations(assessments: ControlAssessment[]): string[] {
        const recs: string[] = [];

        if (assessments.some(a => a.controlId === 'Art.32' && a.status !== 'compliant')) {
            recs.push('Implement additional security measures for personal data processing');
        }

        return recs;
    }
}

interface ComplianceControl {
    id: string;
    name: string;
    relevantCategories: string[];
}
