import { CryptoUtils } from './crypto.js';
import { ContentValidator } from './validator.js';

class SecureClipBackground {
  constructor() {
    this.apiUrl = 'http://localhost:5000/api';
    this.authToken = null;
    this.openaiKey = null;
    this.settings = {
      autoScan: true,
      aiScan: true
    };
    this.domainRules = [];
    this.cryptoUtils = new CryptoUtils();
    this.validator = new ContentValidator();
    this.init();
  }

  async init() {
    try {
      const settings = await chrome.storage.sync.get([
        'authToken', 'apiUrl', 'openaiKey', 'autoScan', 'aiScan'
      ]);
      if (settings.authToken) this.authToken = settings.authToken;
      if (settings.apiUrl) this.apiUrl = settings.apiUrl;
      if (settings.openaiKey) this.openaiKey = settings.openaiKey;
      this.settings.autoScan = settings.autoScan !== false;
      this.settings.aiScan = settings.aiScan !== false;

      if (this.authToken) {
        await this.loadRules();
        setInterval(() => this.loadRules(), 300000); // Every 5 minutes
      }

      chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        this.handleMessage(message, sender, sendResponse);
        return true;
      });

      chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
        if (changeInfo.status === 'complete' && tab.url) {
          this.checkTabSecurity(tab);
        }
      });

      this.setupClipboardMonitoring();
    } catch (error) {
      console.error("Failed to initialize background service:", error);
    }
  }

  async loadRules() {
    if (!this.authToken) return;
    try {
      const response = await fetch(`${this.apiUrl}/domain-rules`, {
        headers: {
          'Authorization': `Bearer ${this.authToken}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        this.domainRules = data.rules || [];
        await this.broadcastRulesUpdate();
      } else {
        console.warn("Failed to load domain rules:", response.statusText);
      }
    } catch (error) {
      console.error("Error fetching domain rules:", error);
    }
  }

  async broadcastRulesUpdate() {
    try {
      const tabs = await chrome.tabs.query({});
      for (const tab of tabs) {
        if (tab.id) {
          try {
            await chrome.tabs.sendMessage(tab.id, {
              type: 'RULES_UPDATE',
              domainRules: this.domainRules,
              settings: this.settings
            });
          } catch (e) {
            // Ignore errors if tab can't receive messages
          }
        }
      }
    } catch (error) {
      console.error("Rule broadcast failed:", error);
    }
  }

  extractDomain(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return '';
    }
  }

  isDomainBlocked(domain) {
    return this.domainRules.some(rule =>
      rule.rule_type === 'blacklist' &&
      (rule.domain === domain || domain.includes(rule.domain))
    );
  }

  isDomainRestricted(domain) {
    const hasWhitelist = this.domainRules.some(rule => rule.rule_type === 'whitelist');
    if (!hasWhitelist) return false;
    return !this.domainRules.some(rule =>
      rule.rule_type === 'whitelist' &&
      (rule.domain === domain || domain.includes(rule.domain))
    );
  }

  checkTabSecurity(tab) {
    if (!tab.url || !this.authToken) return;
    const domain = this.extractDomain(tab.url);
    const isBlocked = this.isDomainBlocked(domain);
    const isRestricted = this.isDomainRestricted(domain);

    if (isBlocked) {
      chrome.action.setBadgeText({ text: '🚫', tabId: tab.id });
      chrome.action.setBadgeBackgroundColor({ color: '#ef4444', tabId: tab.id });
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: 'SecureClip Warning',
        message: `Blocked domain detected: ${domain}`
      });
    } else if (isRestricted) {
      chrome.action.setBadgeText({ text: '⚠️', tabId: tab.id });
      chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', tabId: tab.id });
    } else {
      chrome.action.setBadgeText({ text: '', tabId: tab.id });
    }
  }

  setupClipboardMonitoring() {
    let lastClipboardHash = '';

    setInterval(async () => {
      if (!this.settings.autoScan || !this.authToken) return;
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          const currentHash = await this.cryptoUtils.generateHash(text);
          if (currentHash !== lastClipboardHash) {
            lastClipboardHash = currentHash;
            await this.scanClipboardContent(text);
          }
        }
      } catch (error) {
        console.debug('Clipboard access limited:', error.message);
      }
    }, 2000);
  }

  async scanClipboardContent(content) {
    try {
      let result;
      if (this.settings.aiScan && this.openaiKey) {
        const response = await fetch(`${this.apiUrl}/content/scan`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.authToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ content })
        });
        if (response.ok) {
          result = await response.json();
        } else {
          throw new Error('AI scan failed');
        }
      } else {
        result = this.validator.validateContent(content);
      }

      if (!result.is_safe) {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon48.png',
          title: 'SecureClip Alert',
          message: `Threat detected in clipboard: ${result.threats?.[0] || 'Security risk'}`
        });
        await this.logSecurityIncident({
          type: 'clipboard_threat',
          content_hash: await this.cryptoUtils.generateHash(content),
          threats: result.threats,
          classification: result.classification
        });
      }
    } catch (error) {
      console.error("Clipboard scan error:", error);
    }
  }

  async handleMessage(message, sender, sendResponse) {
    try {
      switch (message.type) {
        case 'AUTH_UPDATED':
          this.authToken = message.authToken;
          this.apiUrl = message.apiUrl;
          this.openaiKey = message.openaiKey;
          await this.loadRules();
          sendResponse({ success: true });
          break;

        case 'AUTH_CLEARED':
          this.authToken = null;
          this.openaiKey = null;
          this.domainRules = [];
          sendResponse({ success: true });
          break;

        case 'SETTINGS_CHANGED':
          this.settings = { ...this.settings, ...message };
          await this.broadcastRulesUpdate();
          sendResponse({ success: true });
          break;

        case 'VALIDATE_PASTE':
          const validation = await this.validatePaste(message.data);
          sendResponse(validation);
          break;

        case 'GET_RULES':
          sendResponse({
            domainRules: this.domainRules,
            settings: this.settings
          });
          break;

        case 'LOG_INCIDENT':
          await this.logSecurityIncident(message.data);
          sendResponse({ success: true });
          break;

        default:
          sendResponse({ error: 'Unknown message type' });
      }
    } catch (error) {
      console.error('Message handling error:', error);
      sendResponse({ error: error.message });
    }
  }

  async validatePaste(data) {
    if (!this.authToken) {
      return { allowed: false, reason: 'Not authenticated' };
    }
    try {
      const response = await fetch(`${this.apiUrl}/paste-control/validate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.authToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      });
      if (response.ok) {
        return await response.json();
      } else {
        return { allowed: false, reason: 'Validation failed' };
      }
    } catch (error) {
      console.error('Paste validation error:', error);
      const domain = data.domain;
      if (this.isDomainBlocked(domain)) {
        return { allowed: false, reason: 'Domain blocked by policy' };
      }
      return { allowed: true, reason: 'Local validation passed' };
    }
  }

  async logSecurityIncident(data) {
    if (!this.authToken) return;
    try {
      await fetch(`${this.apiUrl}/audit/logs`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.authToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          action: 'security_incident',
          details: data,
          timestamp: new Date().toISOString(),
          source: 'browser_extension'
        })
      });
    } catch (error) {
      console.error('Failed to log security incident:', error);
    }
  }
}

// Initialize background service
const secureClipBackground = new SecureClipBackground();

export { secureClipBackground };