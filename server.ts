import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import { execFile, exec } from 'child_process';
import { promisify } from 'util';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const execPromise = promisify(exec);
const execFilePromise = promisify(execFile);

async function startServer() {
  const app = express();
  const PORT = 3000;
  const uploadsDir = path.resolve(__dirname, 'cybershield/backend/uploads');
  const pythonScript = path.resolve(__dirname, 'cybershield/backend/analyzer/run_analysis.py');

  fs.mkdirSync(uploadsDir, { recursive: true });

  app.use(express.json());

  // 1. Health check - Section 44
  app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'CyberShield Backend' });
  });

  // 2. Demo mode endpoint - Section 29
  app.get('/demo', async (req, res) => {
    try {
      const { stdout } = await execFilePromise('python3', [pythonScript, '--demo'], {
        cwd: path.resolve(__dirname, 'cybershield/backend')
      });
      res.json(JSON.parse(stdout));
    } catch (err: any) {
      res.status(500).json({ error: `Demo generation failed: ${err.message}` });
    }
  });

  // 2.1 Sample PCAPs endpoints
  const samplesDir = path.resolve(__dirname, 'tests/test_files');
  app.get('/api/sample-pcaps', (req, res) => {
    const samples = [
      {
        filename: 'port_scan.pcap',
        name: 'Horizontal Port Scan Reconnaissance',
        category: 'Port Scan',
        description: 'Host 192.168.1.200 scanning 35 distinct destination ports with SYN probes.',
        size: fs.existsSync(path.join(samplesDir, 'port_scan.pcap')) ? fs.statSync(path.join(samplesDir, 'port_scan.pcap')).size : 0
      },
      {
        filename: 'dos_syn_flood.pcap',
        name: 'High-Velocity SYN Flood (DoS)',
        category: 'DoS/DDoS',
        description: '120 packets in ~0.35s (>300 pkt/s) concentrated on target 10.0.0.50.',
        size: fs.existsSync(path.join(samplesDir, 'dos_syn_flood.pcap')) ? fs.statSync(path.join(samplesDir, 'dos_syn_flood.pcap')).size : 0
      },
      {
        filename: 'ssh_brute_force.pcap',
        name: 'SSH Credential Brute Force (Port 22)',
        category: 'Brute Force',
        description: '18 rapid repeated connection attempts to SSH daemon with aborted handshakes.',
        size: fs.existsSync(path.join(samplesDir, 'ssh_brute_force.pcap')) ? fs.statSync(path.join(samplesDir, 'ssh_brute_force.pcap')).size : 0
      },
      {
        filename: 'botnet_beacon.pcap',
        name: 'Periodic C2 Heartbeat Beaconing',
        category: 'Possible Botnet/C2',
        description: 'Regular 1.0s periodic telemetry heartbeats between internal host and external C2.',
        size: fs.existsSync(path.join(samplesDir, 'botnet_beacon.pcap')) ? fs.statSync(path.join(samplesDir, 'botnet_beacon.pcap')).size : 0
      },
      {
        filename: 'normal_traffic.pcap',
        name: 'Standard Clean HTTP & DNS Traffic',
        category: 'Benign',
        description: 'Normal web browsing traffic with complete 3-way handshakes and clean teardowns.',
        size: fs.existsSync(path.join(samplesDir, 'normal_traffic.pcap')) ? fs.statSync(path.join(samplesDir, 'normal_traffic.pcap')).size : 0
      },
      {
        filename: 'insufficient_evidence.pcap',
        name: 'Minimal Telemetry Capture (2 packets)',
        category: 'Insufficient Evidence',
        description: 'Only 2 packets captured; validates graceful handling without false alarms.',
        size: fs.existsSync(path.join(samplesDir, 'insufficient_evidence.pcap')) ? fs.statSync(path.join(samplesDir, 'insufficient_evidence.pcap')).size : 0
      },
      {
        filename: 'valid_test.pcapng',
        name: 'PCAP Next Generation Capture (.pcapng)',
        category: 'PCAPNG Format',
        description: 'Valid Section Header & Enhanced Packet Blocks (EPB) binary capture format.',
        size: fs.existsSync(path.join(samplesDir, 'valid_test.pcapng')) ? fs.statSync(path.join(samplesDir, 'valid_test.pcapng')).size : 0
      }
    ];
    res.json({ samples });
  });

  app.post('/api/analyze-sample', async (req, res) => {
    const filename = req.body?.filename;
    if (!filename) {
      return res.status(400).json({ error: 'Sample filename required.' });
    }
    const safeFilename = path.basename(filename);
    const samplePath = path.join(samplesDir, safeFilename);

    if (!fs.existsSync(samplePath)) {
      return res.status(404).json({ error: `Sample capture '${safeFilename}' not found.` });
    }

    try {
      const { stdout } = await execFilePromise(
        'python3', 
        [pythonScript, samplePath, safeFilename],
        { cwd: path.resolve(__dirname, 'cybershield/backend'), maxBuffer: 10 * 1024 * 1024 }
      );
      res.json(JSON.parse(stdout));
    } catch (pyErr: any) {
      res.status(500).json({ error: `Analysis failed: ${pyErr.stderr || pyErr.message}` });
    }
  });

  app.get('/api/download-sample/:filename', (req, res) => {
    const safeFilename = path.basename(req.params.filename);
    const samplePath = path.join(samplesDir, safeFilename);
    if (!fs.existsSync(samplePath)) {
      return res.status(404).send('Sample file not found');
    }
    res.download(samplePath, safeFilename);
  });

  // 3. Stats endpoint
  app.get('/stats', async (req, res) => {
    try {
      const pyCmd = `import sys; sys.path.insert(0, '.'); from models.database import get_dashboard_stats; import json; print(json.dumps(get_dashboard_stats()))`;
      const { stdout } = await execPromise(`python3 -c "${pyCmd}"`, {
        cwd: path.resolve(__dirname, 'cybershield/backend')
      });
      res.json(JSON.parse(stdout));
    } catch (err: any) {
      res.status(500).json({ error: `Stats retrieval failed: ${err.message}` });
    }
  });

  // 4. File Upload & Real PCAP Analysis - Section 4 & 27
  app.post('/upload', async (req, res) => {
    try {
      const fileData = await parseMultipart(req);
      const filename = fileData.filename;
      const ext = path.extname(filename).toLowerCase();

      if (ext !== '.pcap' && ext !== '.pcapng') {
        return res.status(400).json({
          error: 'Invalid file type. Only .pcap and .pcapng files are supported.'
        });
      }

      if (fileData.buffer.length > 50 * 1024 * 1024) {
        return res.status(400).json({
          error: 'File exceeds the 50 MB limit.'
        });
      }

      const safeId = Math.random().toString(36).substring(2, 10);
      const safeFilename = path.basename(filename);
      const tempPath = path.join(uploadsDir, `${safeId}_${safeFilename}`);

      fs.writeFileSync(tempPath, fileData.buffer);

      // Invoke Python PCAP Analysis engine
      try {
        const { stdout } = await execFilePromise(
          'python3', 
          [pythonScript, tempPath, safeFilename],
          { cwd: path.resolve(__dirname, 'cybershield/backend'), maxBuffer: 10 * 1024 * 1024 }
        );

        const result = JSON.parse(stdout);
        res.json(result);
      } catch (pyErr: any) {
        const errMsg = pyErr.stderr || pyErr.message;
        try {
          const parsedErr = JSON.parse(pyErr.stderr || '{}');
          if (parsedErr.error) {
            return res.status(400).json({ error: parsedErr.error });
          }
        } catch {
          // not json
        }
        res.status(400).json({
          error: `The uploaded PCAP could not be parsed: ${errMsg.trim()}`
        });
      } finally {
        // Safe cleanup
        if (fs.existsSync(tempPath)) {
          fs.unlinkSync(tempPath);
        }
      }
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // 5. Results endpoint
  app.get('/results/:analysis_id', async (req, res) => {
    const aid = req.params.analysis_id;
    try {
      const pyCmd = `import sys; sys.path.insert(0, '.'); from models.database import get_analysis; import json; r = get_analysis('${aid}'); print(json.dumps(r) if r else 'null')`;
      const { stdout } = await execPromise(`python3 -c "${pyCmd}"`, {
        cwd: path.resolve(__dirname, 'cybershield/backend')
      });
      const data = JSON.parse(stdout);
      if (!data) {
        return res.status(404).json({ error: `Analysis with ID '${aid}' not found.` });
      }
      res.json(data);
    } catch (err: any) {
      res.status(500).json({ error: `Failed to retrieve analysis: ${err.message}` });
    }
  });

  // 6. History endpoint
  app.get('/history', async (req, res) => {
    const search = (req.query.search as string) || '';
    const severity = (req.query.severity as string) || 'all';
    try {
      const pyCmd = `import sys; sys.path.insert(0, '.'); from models.database import get_history; import json; r = get_history('${search}', '${severity}'); print(json.dumps({'history': r}))`;
      const { stdout } = await execPromise(`python3 -c "${pyCmd}"`, {
        cwd: path.resolve(__dirname, 'cybershield/backend')
      });
      res.json(JSON.parse(stdout));
    } catch (err: any) {
      res.status(500).json({ error: `Failed to query history: ${err.message}` });
    }
  });

  // 7. Delete analysis from history
  app.delete('/history/:analysis_id', async (req, res) => {
    const aid = req.params.analysis_id;
    try {
      const pyCmd = `import sys; sys.path.insert(0, '.'); from models.database import delete_analysis; ok = delete_analysis('${aid}'); print('1' if ok else '0')`;
      const { stdout } = await execPromise(`python3 -c "${pyCmd}"`, {
        cwd: path.resolve(__dirname, 'cybershield/backend')
      });
      if (stdout.trim() === '1') {
        res.json({ message: `Analysis '${aid}' deleted successfully.` });
      } else {
        res.status(404).json({ error: `Analysis '${aid}' not found.` });
      }
    } catch (err: any) {
      res.status(500).json({ error: `Failed to delete analysis: ${err.message}` });
    }
  });

  // Mount Vite middlewares for development on port 3000
  const vite = await createViteServer({
    server: { middlewareMode: true },
    appType: 'spa',
  });
  app.use(vite.middlewares);

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CyberShield] Platform running on http://0.0.0.0:${PORT}`);
  });
}

function parseMultipart(req: express.Request, maxBytes = 50 * 1024 * 1024): Promise<{ filename: string; buffer: Buffer }> {
  return new Promise((resolve, reject) => {
    const contentType = req.headers['content-type'] || '';
    if (!contentType.includes('multipart/form-data')) {
      return reject(new Error('Invalid content type. Expected multipart/form-data.'));
    }
    const boundaryMatch = contentType.match(/boundary=([^;]+)/);
    if (!boundaryMatch) {
      return reject(new Error('Boundary delimiter not found in Content-Type header.'));
    }
    const boundary = boundaryMatch[1].trim().replace(/^"|"$/g, '');
    const boundaryBuffer = Buffer.from('--' + boundary);

    const chunks: Buffer[] = [];
    let totalLen = 0;

    req.on('data', (chunk: Buffer) => {
      totalLen += chunk.length;
      if (totalLen > maxBytes) {
        req.destroy();
        return reject(new Error('File exceeds the 50 MB limit.'));
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      const fullBuffer = Buffer.concat(chunks);
      let startIdx = fullBuffer.indexOf(boundaryBuffer);

      while (startIdx !== -1) {
        startIdx += boundaryBuffer.length;
        if (fullBuffer.slice(startIdx, startIdx + 2).toString() === '--') {
          break;
        }
        if (fullBuffer.slice(startIdx, startIdx + 2).toString() === '\r\n') {
          startIdx += 2;
        }

        const nextBoundaryIdx = fullBuffer.indexOf(boundaryBuffer, startIdx);
        if (nextBoundaryIdx === -1) break;

        const partBuffer = fullBuffer.slice(startIdx, nextBoundaryIdx - 2);
        const headerEndIdx = partBuffer.indexOf(Buffer.from('\r\n\r\n'));
        if (headerEndIdx !== -1) {
          const headerStr = partBuffer.slice(0, headerEndIdx).toString('latin1');
          const fileMatch = headerStr.match(/name="([^"]+)";\s+filename="([^"]+)"/);
          if (fileMatch) {
            const filename = fileMatch[2];
            const fileData = partBuffer.slice(headerEndIdx + 4);
            return resolve({ filename, buffer: fileData });
          }
        }

        startIdx = nextBoundaryIdx;
      }

      reject(new Error('No valid file part detected in request body.'));
    });

    req.on('error', (err) => reject(err));
  });
}

startServer();
