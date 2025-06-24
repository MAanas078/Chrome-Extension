// crypto.js - AES-GCM encryption + SHA-256 hashing utilities

export class CryptoUtils {
  constructor() {
    this.ALGORITHM = 'AES-GCM';
    this.KEY_LENGTH = 256;
  }

  // Generate a new AES-GCM key
  async generateKey() {
    return await crypto.subtle.generateKey(
      { name: this.ALGORITHM, length: this.KEY_LENGTH },
      true,
      ['encrypt', 'decrypt']
    );
  }

  // Import raw key from ArrayBuffer
  async importKey(keyBytes) {
    return await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: this.ALGORITHM, length: this.KEY_LENGTH },
      true,
      ['encrypt', 'decrypt']
    );
  }

  // Export raw key as ArrayBuffer
  async exportKey(key) {
    return await crypto.subtle.exportKey('raw', key);
  }

  // Encrypt data using AES-GCM
  async encrypt(data, key) {
    try {
      const encoder = new TextEncoder();
      const dataBytes = encoder.encode(data);
      const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV

      const encrypted = await crypto.subtle.encrypt(
        { name: this.ALGORITHM, iv },
        key,
        dataBytes
      );

      const result = new Uint8Array(iv.length + encrypted.byteLength);
      result.set(iv);
      result.set(new Uint8Array(encrypted), iv.length);

      return this.arrayBufferToBase64(result.buffer);
    } catch (error) {
      console.error("Encryption failed:", error);
      throw new Error("Encryption failed");
    }
  }

  // Decrypt data using AES-GCM
  async decrypt(encryptedData, key) {
    try {
      const data = this.base64ToArrayBuffer(encryptedData);
      const iv = data.slice(0, 12); // First 12 bytes for IV
      const encrypted = data.slice(12);

      const decrypted = await crypto.subtle.decrypt(
        { name: this.ALGORITHM, iv },
        key,
        encrypted
      );

      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch (error) {
      console.error("Decryption failed:", error);
      throw new Error("Decryption failed");
    }
  }

  // Generate SHA-256 hash of content
  async generateHash(content) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(content);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (error) {
      console.error("Hash generation failed:", error);
      return '';
    }
  }

  // Helper: Convert ArrayBuffer to Base64
  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  // Helper: Convert Base64 to ArrayBuffer
  base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer; // <-- FIXED: return ArrayBuffer, not Uint8Array
  }
}