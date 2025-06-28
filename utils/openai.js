// openai.js

/**
 * OpenAIService
 * -------------
 * This class handles communication with the OpenAI API to analyze clipboard content
 * for sensitive data or security threats.
 *
 * Usage:
 *   const openai = new OpenAIService(apiKey);
 *   const result = await openai.scanForThreats(text);
 */
class OpenAIService {
  /**
   * @param {string} apiKey - The OpenAI API key.
   */
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.apiUrl = 'https://api.openai.com/v1/chat/completions';
    this.model = 'gpt-3.5-turbo'; // You can change the model if needed
  }

  /**
   * Scan clipboard content for threats using OpenAI.
   * @param {string} content - Clipboard content to scan.
   * @returns {Promise<{ is_safe: boolean, threats: string[], ai_analysis: string }>}
   */
  async scanForThreats(content) {
    // Build prompt for OpenAI
    const prompt = `
You are a cybersecurity expert AI. Analyze the following clipboard content for the presence of sensitive data, secrets, credentials, malware, suspicious links, or other security threats.
Classify as "safe" or "blocked". If blocked, list threats found and explain why.

Clipboard Content:
${content}

Respond in JSON:
{
  "is_safe": true/false,
  "threats": [ "threat description 1", "threat description 2" ],
  "ai_analysis": "detailed reasoning"
}
    `.trim();

    const body = {
      model: this.model,
      messages: [
        { role: "system", content: "You are a helpful cybersecurity assistant." },
        { role: "user", content: prompt }
      ],
      max_tokens: 400,
      temperature: 0.1
    };

    // Call OpenAI API
    const response = await fetch(this.apiUrl, {
      method: "POST",
      headers: {
        "Authorization": **Bearer ${this.apiKey}**,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      throw new Error(**OpenAI API error: ${response.status} ${response.statusText}**);
    }

    const data = await response.json();

    // Try to extract JSON from the AI's response
    let aiResult = {};
    try {
      const msg = data.choices[0].message.content;
      // Extract JSON block from the response
      const match = msg.match(/\{[\s\S]*\}/);
      aiResult = match ? JSON.parse(match[0]) : {};
    } catch (err) {
      throw new Error("Failed to parse OpenAI response as JSON");
    }

    // Fallback defaults
    return {
      is_safe: !!aiResult.is_safe,
      threats: Array.isArray(aiResult.threats) ? aiResult.threats : [],
      ai_analysis: aiResult.ai_analysis || "No analysis provided."
    };
  }
}

// If using ES6 modules, export the class
// export default OpenAIService;
