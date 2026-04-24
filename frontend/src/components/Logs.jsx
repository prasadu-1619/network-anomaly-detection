import React, { useState, useEffect } from 'react';
import { BentoBox, BentoHeader } from './ui/Bento';
import { Download, CloudDownload } from 'lucide-react';

const API_BASE = "http://127.0.0.1:8050";

export function Logs() {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/api/traffic_data`)
      .then(res => res.json())
      .then(d => {
        setData(d.slice(-100)); // show last 100 on screen to avoid lag
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const downloadCSV = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/traffic_data`);
      const allData = await res.json();
      if (!allData.length) return;
      
      const keys = Object.keys(allData[0]);
      const csvString = [
        keys.join(','),
        ...allData.map(row => keys.map(k => row[k]).join(','))
      ].join('\n');
      
      const blob = new Blob([csvString], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.setAttribute('hidden', '');
      a.setAttribute('href', url);
      a.setAttribute('download', `export_${new Date().toISOString().replace(/[:.]/g, '')}.csv`);
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <BentoBox delay={0.1}>
      <BentoHeader title="Data Export" icon={CloudDownload} colorClasses="text-cyber-success" tooltip="Export session traffic to CSV for external analysis." />
      
      <div className="flex justify-between items-center mb-4">
        <span className="text-sm text-cyber-text">Showing latest 100 records in UI. Export downloads full history.</span>
        <button 
          onClick={downloadCSV}
          className="flex items-center gap-2 px-4 py-2 bg-cyber-accent/10 hover:bg-cyber-accent/20 border border-cyber-accent/30 hover:border-cyber-accent text-cyber-accent rounded-lg transition-all text-sm font-semibold shadow-cyber"
        >
          <Download size={16} /> Save CSV
        </button>
      </div>

      <div className="overflow-x-auto overflow-y-auto max-h-[500px] border border-white/5 rounded-lg">
        {loading ? (
          <div className="text-center p-10 text-cyber-text">Loading logs...</div>
        ) : (
          <table className="w-full text-left text-xs whitespace-nowrap">
            <thead className="bg-[#1a1a3e] sticky top-0 shadow">
              <tr>
                <th className="p-3 text-cyber-text font-semibold border-b border-white/10">Timestamp</th>
                <th className="p-3 text-cyber-text font-semibold border-b border-white/10">Protocol</th>
                <th className="p-3 text-cyber-text font-semibold border-b border-white/10">Bytes Sent</th>
                <th className="p-3 text-cyber-text font-semibold border-b border-white/10">Bytes Recv</th>
                <th className="p-3 text-cyber-text font-semibold border-b border-white/10">Packets</th>
                <th className="p-3 text-cyber-text font-semibold border-b border-white/10">Anomaly?</th>
                <th className="p-3 text-cyber-text font-semibold border-b border-white/10">Score</th>
              </tr>
            </thead>
            <tbody>
              {data.map((row, i) => (
                <tr key={i} className="hover:bg-white/5 border-b border-white/5 transition-colors">
                  <td className="p-3 text-gray-300">{new Date(row.timestamp).toLocaleTimeString()}</td>
                  <td className="p-3 text-gray-300 font-mono">{row.protocol}</td>
                  <td className="p-3 text-gray-300">{row.bytes_sent}</td>
                  <td className="p-3 text-gray-300">{row.bytes_received}</td>
                  <td className="p-3 text-gray-300">{row.packets}</td>
                  <td className={`p-3 font-semibold ${row.is_anomaly === 'Yes' ? 'text-cyber-danger' : 'text-cyber-success'}`}>{row.is_anomaly}</td>
                  <td className="p-3 text-gray-300 font-mono">{parseFloat(row.anomaly_score).toFixed(3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </BentoBox>
  );
}
