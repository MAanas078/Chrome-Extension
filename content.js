// Content script for SecureClip extension
class SecureClipContent {
  constructor() {
    this.domainRules = []
    this.applicationRules = []
    this.deviceId = this.generateDeviceId()
    this.init()
  }

  async init() {
    // Request rules from background script
    const rulesResponse = await chrome.runtime.sendMessage({ type: 'GET_RULES' })
    if (rulesResponse) {
      this.domainRules = rulesResponse.domainRules || []
      this.applicationRules = rulesResponse.applicationRules || []
    }

    // Listen for rule updates
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === 'RULES_UPDATE') {
        this.domainRules = message.domainRules
        this.applicationRules = message.applicationRules
      }
    })

    // Monitor paste events
    this.monitorPasteEvents()
    
    // Inject script to monitor clipboard API usage
    this.injectClipboardMonitor()
  }

  generateDeviceId() {
    let deviceId = localStorage.getItem('secureclip_device_id')
    if (!deviceId) {
      deviceId = 'browser_' + Math.random().toString(36).substr(2, 9)
      localStorage.setItem('secureclip_device_id', deviceId)
    }
    return deviceId
  }

  monitorPasteEvents() {
    document.addEventListener('paste', async (event) => {
      const domain = window.location.hostname
      const contentHash = await this.generateContentHash(event.clipboardData?.getData('text') || '')
      
      const validation = await chrome.runtime.sendMessage({
        type: 'VALIDATE_PASTE',
        data: {
          domain,
          deviceId: this.deviceId,
          contentHash
        }
      })

      if (!validation.allowed) {
        event.preventDefault()
        event.stopPropagation()
        this.showBlockedNotification(validation.reason)
      } else {
        // Log successful paste
        chrome.runtime.sendMessage({
          type: 'LOG_CLIPBOARD_EVENT',
          data: {
            action: 'paste',
            domain,
            status: 'allowed',
            contentHash
          }
        })
      }
    }, true)

    // Also monitor programmatic clipboard access
    this.interceptClipboardAPI()
  }

  interceptClipboardAPI() {
    if (!navigator.clipboard) return;
    const originalRead = navigator.clipboard.read
    const originalReadText = navigator.clipboard.readText
    const originalWrite = navigator.clipboard.write
    const originalWriteText = navigator.clipboard.writeText

    navigator.clipboard.read = async (...args) => {
      const result = await this.validateClipboardAccess('read')
      if (!result.allowed) {
        throw new Error(`Clipboard access blocked: ${result.reason}`)
      }
      return originalRead.apply(navigator.clipboard, args)
    }

    navigator.clipboard.readText = async (...args) => {
      const result = await this.validateClipboardAccess('read')
      if (!result.allowed) {
        throw new Error(`Clipboard access blocked: ${result.reason}`)
      }
      return originalReadText.apply(navigator.clipboard, args)
    }

    navigator.clipboard.write = async (data, ...args) => {
      const text = await this.extractTextFromClipboardItems(data)
      const contentHash = await this.generateContentHash(text)
      
      const result = await this.validateClipboardAccess('write', contentHash)
      if (!result.allowed) {
        throw new Error(`Clipboard access blocked: ${result.reason}`)
      }
      return originalWrite.apply(navigator.clipboard, [data, ...args])
    }

    navigator.clipboard.writeText = async (text, ...args) => {
      const contentHash = await this.generateContentHash(text)
      
      const result = await this.validateClipboardAccess('write', contentHash)
      if (!result.allowed) {
        throw new Error(`Clipboard access blocked: ${result.reason}`)
      }
      return originalWriteText.apply(navigator.clipboard, [text, ...args])
    }
  }

  async validateClipboardAccess(action, contentHash = '') {
    const domain = window.location.hostname
    
    return await chrome.runtime.sendMessage({
      type: 'VALIDATE_PASTE',
      data: {
        domain,
        deviceId: this.deviceId,
        contentHash
      }
    })
  }

  async extractTextFromClipboardItems(items) {
    try {
      for (const item of items) {
        if (item.types.includes('text/plain')) {
          const blob = await item.getType('text/plain')
          return await blob.text()
        }
      }
      return ''
    } catch {
      return ''
    }
  }

  async generateContentHash(content) {
    const encoder = new TextEncoder()
    const data = encoder.encode(content)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
  }

  injectClipboardMonitor() {
    const script = document.createElement('script')
    script.src = chrome.runtime.getURL('injected.js')
    script.onload = function() {
      this.remove()
    }
    ;(document.head || document.documentElement).appendChild(script)
  }

  showBlockedNotification(reason) {
    // Create a notification element
    const notification = document.createElement('div')
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #ff4444;
      color: white;
      padding: 12px 20px;
      border-radius: 6px;
      font-family: Arial, sans-serif;
      font-size: 14px;
      z-index: 10000;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      max-width: 300px;
    `
    notification.textContent = `🚫 Paste blocked: ${reason}`
    
    document.body.appendChild(notification)
    
    // Auto-remove after 3 seconds
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification)
      }
    }, 3000)
  }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => new SecureClipContent())
} else {
  new SecureClipContent()
}
