
// Injected script to monitor clipboard events at the page level
(function() {
  'use strict'

  // Monitor document events that might indicate clipboard usage
  const originalExecCommand = document.execCommand
  
  document.execCommand = function(command, ...args) {
    if (command === 'paste' || command === 'copy') {
      window.postMessage({
        type: 'CLIPBOARD_COMMAND',
        command: command,
        timestamp: Date.now()
      }, '*')
    }
    return originalExecCommand.apply(document, [command, ...args])
  }

  // Monitor keyboard shortcuts
  document.addEventListener('keydown', function(event) {
    if ((event.ctrlKey || event.metaKey) && (event.key === 'v' || event.key === 'V')) {
      window.postMessage({
        type: 'PASTE_SHORTCUT',
        timestamp: Date.now(),
        target: event.target.tagName
      }, '*')
    }
    
    if ((event.ctrlKey || event.metaKey) && (event.key === 'c' || event.key === 'C')) {
      window.postMessage({
        type: 'COPY_SHORTCUT',
        timestamp: Date.now(),
        target: event.target.tagName
      }, '*')
    }
  })

  // Listen for messages from content script
  window.addEventListener('message', function(event) {
    if (event.source !== window) return
    
    if (event.data.type === 'CLIPBOARD_COMMAND' || 
        event.data.type === 'PASTE_SHORTCUT' || 
        event.data.type === 'COPY_SHORTCUT') {
      // Forward to content script via custom event
      document.dispatchEvent(new CustomEvent('secureclip_event', {
        detail: event.data
      }))
    }
  })
})()
