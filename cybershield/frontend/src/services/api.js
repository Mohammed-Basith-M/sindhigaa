/**
 * CyberShield Frontend API Service
 * Centralizes REST communication with the Flask / Python backend.
 * Uses VITE_API_URL environment variable with graceful fallback to relative / localhost routes.
 */

const BASE_URL = import.meta.env.VITE_API_URL || '';

export const api = {
  /**
   * Health check endpoint
   */
  async checkHealth() {
    try {
      const res = await fetch(`${BASE_URL}/health`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      return { status: 'offline', error: err.message };
    }
  },

  /**
   * Upload real .pcap or .pcapng file
   */
  async uploadPCAP(file, onProgress) {
    const formData = new FormData();
    formData.append('file', file);

    const xhr = new XMLHttpRequest();
    return new Promise((resolve, reject) => {
      xhr.open('POST', `${BASE_URL}/upload`);

      if (onProgress && xhr.upload) {
        xhr.upload.onprogress = (event) => {
          if (event.lengthComputable) {
            const percent = Math.round((event.loaded / event.total) * 100);
            onProgress(percent);
          }
        };
      }

      xhr.onload = () => {
        try {
          const data = JSON.parse(xhr.responseText);
          if (xhr.status >= 200 && xhr.status < 300) {
            resolve(data);
          } else {
            reject(new Error(data.error || `Upload failed with status ${xhr.status}`));
          }
        } catch {
          reject(new Error(`Failed to parse server response (${xhr.status})`));
        }
      };

      xhr.onerror = () => {
        reject(new Error('Network error during PCAP transmission. Ensure backend is running.'));
      };

      xhr.send(formData);
    });
  },

  /**
   * Fetch analysis dossier by ID
   */
  async getAnalysis(analysisId) {
    const res = await fetch(`${BASE_URL}/results/${analysisId}`);
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `Failed to fetch analysis ${analysisId}`);
    }
    return await res.json();
  },

  /**
   * Fetch historical analysis records
   */
  async getHistory(search = '', severity = 'all') {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (severity && severity !== 'all') params.append('severity', severity);

    const res = await fetch(`${BASE_URL}/history?${params.toString()}`);
    if (!res.ok) throw new Error(`Failed to fetch history (${res.status})`);
    const data = await res.json();
    return data.history || [];
  },

  /**
   * Delete an analysis from the ledger
   */
  async deleteAnalysis(analysisId) {
    const res = await fetch(`${BASE_URL}/history/${analysisId}`, {
      method: 'DELETE'
    });
    if (!res.ok) throw new Error('Failed to delete analysis');
    return await res.json();
  },

  /**
   * Trigger Demo Mode (sample synthetic capture)
   */
  async getDemoAnalysis() {
    const res = await fetch(`${BASE_URL}/demo`);
    if (!res.ok) throw new Error('Failed to load demo scenario');
    return await res.json();
  },

  /**
   * Get dashboard summary cards
   */
  async getStats() {
    const res = await fetch(`${BASE_URL}/stats`);
    if (!res.ok) throw new Error('Failed to fetch stats');
    return await res.json();
  },

  /**
   * Get list of downloadable test captures
   */
  async getSamplePCAPs() {
    try {
      const res = await fetch(`${BASE_URL}/api/sample-pcaps`);
      if (!res.ok) return [];
      const data = await res.json();
      return data.samples || [];
    } catch {
      return [];
    }
  },

  /**
   * Run real analysis on a server-side test capture
   */
  async analyzeSample(filename) {
    const res = await fetch(`${BASE_URL}/api/analyze-sample`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Failed to analyze sample ${filename}`);
    }
    return await res.json();
  },

  /**
   * Download sample PCAP binary
   */
  getSampleDownloadUrl(filename) {
    return `${BASE_URL}/api/download-sample/${encodeURIComponent(filename)}`;
  }
};

export default api;
