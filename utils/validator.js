// Content validation and threat detection utilities
class ContentValidator {
  constructor() {
    this.threatPatterns = [
      // Credentials
      {
        name: 'Password Pattern',
        regex: /(?:password|pwd|pass)\s*[:=]\s*\S+/gi,
        severity: 'high',
        description: 'Potential password detected'
      },
      {
        name: 'API Key Pattern',
        regex: /(?:api[_-]?key|token|secret)\s*[:=]\s*[A-Za-z0-9_-]{20,}/gi,
        severity: 'high',
        description: 'Potential API key or token detected'
      },
      {
        name: 'Private Key',
        regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gi,
        severity: 'critical',
        description: 'Private key detected'
      },

      // Personal Information
      {
        name: 'Credit Card',
        regex: /\b(?:\d{4}[\s-]?){3}\d{4}\b/g,
        severity: 'high',
        description: 'Credit card number pattern detected'
      },
      {
        name: 'SSN Pattern',
        regex: /\b\d{3}-\d{2}-\d{4}\b/g,
        severity: 'high',
        description: 'Social Security Number pattern detected'
      },
      {
        name: 'Email Address',
        regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
        severity: 'medium',
        description: 'Email address detected'
      },

      // Malicious Content
      {
        name: 'Suspicious URL',
        regex: /https?:\/\/[^\s]+\.(?:exe|bat|cmd|scr|com|pif|zip)/gi,
        severity: 'critical',
        description: 'Suspicious executable download link'
      },
      {
        name: 'Script Injection',
        regex: /(?:javascript:|data:|vbscript:)/gi,
        severity: 'critical',
        description: 'Potentially dangerous script detected'
      },
      {
        name: 'SQL Injection',
        regex: /(?:union\s+select|drop\s+table|delete\s+from|insert\s+into)/gi,
        severity: 'high',
        description: 'Potential SQL injection pattern'
      },
      {
        name: 'Command Injection',
        regex: /(?:;|\||&|\$\(|\`).+(?:rm\s+-rf|wget|curl|nc\s+)/gi,
        severity: 'critical',
        description: 'Potential command injection'
      },

      // Malware References
      {
        name: 'Malware Keywords',
        regex: /\b(?:malware|virus|trojan|ransomware|keylogger|backdoor|rootkit)\b/gi,
        severity: 'high',
        description: 'Malware-related keywords detected'
      }
    ];

    this.domainWhitelist = [
      'github.com',
      'stackoverflow.com',
      'google.com',
      'microsoft.com',
      'apple.com'
    ];

    this.domainBlacklist = [
      'bit.ly',
      'tinyurl.com',
      't.co'
    ];
  }

  validateContent(content) {
    const threats = [];
    let maxSeverity = 'safe';
    
    // Check against threat patterns
    for (const pattern of this.threatPatterns) {
      const matches = content.match(pattern.regex);
      if (matches) {
        threats.push({
          type: pattern.name,
          description: pattern.description,
          severity: pattern.severity,
          matches: matches.length,
          sample: matches[0].substring(0, 50)
        });

        // Update max severity
        if (pattern.severity === 'critical' || 
           (pattern.severity === 'high' && maxSeverity !== 'critical') ||
           (pattern.severity === 'medium' && maxSeverity === 'safe')) {
          maxSeverity = pattern.severity;
        }
      }
    }

    // Check URLs
    const urlMatches = content.match(/https?:\/\/[^\s]+/gi);
    if (urlMatches) {
      for (const url of urlMatches) {
        const domain = this.extractDomain(url);
        
        if (this.domainBlacklist.includes(domain)) {
          threats.push({
            type: 'Blacklisted Domain',
            description: `Blocked domain: ${domain}`,
            severity: 'high',
            matches: 1,
            sample: url
          });
          if (maxSeverity !== 'critical') maxSeverity = 'high';
        }
      }
    }

    // Determine overall classification
    let classification = 'safe';
    let action = 'allowed';

    if (maxSeverity === 'critical') {
      classification = 'blocked';
      action = 'blocked';
    } else if (maxSeverity === 'high') {
      classification = 'warning';
      action = 'quarantined';
    } else if (maxSeverity === 'medium') {
      classification = 'warning';
      action = 'allowed';
    }

    return {
      is_safe: classification === 'safe',
      classification,
      action,
      threats: threats.map(t => t.description),
      detailed_threats: threats,
      risk_score: this.calculateRiskScore(threats),
      content_type: this.detectContentType(content)
    };
  }

  calculateRiskScore(threats) {
    let score = 0;
    for (const threat of threats) {
      switch (threat.severity) {
        case 'critical': score += 4; break;
        case 'high': score += 3; break;
        case 'medium': score += 2; break;
        case 'low': score += 1; break;
      }
    }
    return Math.min(10, score);
  }

  detectContentType(content) {
    if (content.match(/^[A-Za-z0-9+/]+=*$/)) return 'base64';
    if (content.match(/^[0-9a-f]{32,}$/i)) return 'hash';
    if (content.match(/https?:\/\//)) return 'url';
    if (content.match(/(?:function|class|var|const|let)\s+/)) return 'code';
    if (content.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}/)) return 'email';
    if (content.match(/\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}/)) return 'credentials';
    return 'text';
  }

  extractDomain(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return '';
    }
  }

  isDomainAllowed(domain) {
    if (this.domainBlacklist.includes(domain)) return false;
    if (this.domainWhitelist.length === 0) return true;
    return this.domainWhitelist.includes(domain);
  }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ContentValidator;
} else {
  window.ContentValidator = ContentValidator;
}
