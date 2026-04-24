import React, { useState, useEffect } from 'react';
import { BentoBox, BentoHeader } from './ui/Bento';
import { Sliders, Save, Check, Cpu, Server, Activity } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const API_BASE = "http://127.0.0.1:8050";

export function Settings() {
  const [buffer, setBuffer] = useState(100);
  const [saved, setSaved] = useState(false);
  const [config, setConfig] = useState(null);
  const [stats, setStats] = useState(null);

  useEffect(() => {
    // Fetch both config and stats for model readout
    Promise.all([
      fetch(`${API_BASE}/api/config`).then(r => r.json()),
      fetch(`${API_BASE}/api/stats`).then(r => r.json())
    ]).then(([c, s]) => {
      setConfig(c);
      setBuffer(c.buffer_size);
      setStats(s);
    }).catch(e => console.error(e));
  }, []);

  const handleApply = async () => {
    try {
      await fetch(`${API_BASE}/api/config/buffer_size`, {
        method: 'POST',
        body: JSON.stringify({ buffer_size: parseInt(buffer) })
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch(e) {
      console.error(e);
    }
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* Interactive Settings */}
      <BentoBox delay={0.1}>
        <BentoHeader title="Engine Settings" icon={Sliders} colorClasses="text-cyber-accent" tooltip="Adjust real-time buffer capacity limits." />
        
        <div className="py-2">
          <label className="block text-cyber-text text-sm mb-2 font-semibold tracking-wide">
            Dashboard Window Size (Points)
          </label>
          <div className="flex items-center gap-4 max-w-sm">
            <input 
              type="number" 
              min="10" 
              max="2000"
              value={buffer}
              onChange={(e) => setBuffer(e.target.value)}
              className="flex-1 bg-cyber-dark border border-white/20 rounded-lg px-4 py-2 text-white outline-none focus:border-cyber-accent focus:shadow-[0_0_10px_rgba(0,212,255,0.3)] transition-all font-mono"
            />
            <button 
              onClick={handleApply}
              className="flex items-center justify-center min-w-[100px] h-10 bg-cyber-accent hover:bg-[#00e5ff] text-cyber-dark font-bold rounded-lg transition-transform hover:scale-105 active:scale-95 shadow-cyber border-none"
            >
              <AnimatePresence mode="wait">
                {saved ? (
                  <motion.div key="saved" initial={{ scale: 0 }} animate={{ scale: 1 }} exit={{ scale: 0 }} className="flex items-center gap-1">
                    <Check size={16} /> Saved
                  </motion.div>
                ) : (
                  <motion.div key="apply" initial={{ scale: 0 }} animate={{ scale: 1 }} exit={{ scale: 0 }} className="flex items-center gap-1">
                    <Save size={16} /> Apply
                  </motion.div>
                )}
              </AnimatePresence>
            </button>
          </div>
          <p className="mt-3 text-xs text-[#a8b8d4]">
            Higher values keep more historical data on screen but may impact browser rendering performance. Recommended: 100 - 500.
          </p>
        </div>
      </BentoBox>

      {/* Write-Protected Architecture Info */}
      <BentoBox delay={0.2} className="h-full">
        <BentoHeader title="System Architecture" icon={Server} colorClasses="text-cyber-success" tooltip="Read-only configurations and Machine Learning model state." />
        
        {config && stats ? (
          <div className="flex flex-col gap-4 mt-2">
            <div className="grid grid-cols-2 gap-x-4 gap-y-3">
              <div>
                <p className="text-[#a8b8d4] text-[11px] font-semibold tracking-wider uppercase mb-1 flex items-center gap-1"><Cpu size={12}/> Model Status</p>
                <div className="flex items-center gap-2">
                  <span className={`relative flex h-2 w-2`}>
                    {stats.model_trained && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-success opacity-75"></span>}
                    <span className={`relative inline-flex rounded-full h-2 w-2 ${stats.model_trained ? 'bg-cyber-success' : 'bg-cyber-warning'}`}></span>
                  </span>
                  <p className="text-white font-mono text-sm m-0">
                    {stats.model_trained ? "Trained (Active)" : `Training... (${stats.training_progress}/${stats.training_target})`}
                  </p>
                </div>
              </div>

              <div>
                <p className="text-[#a8b8d4] text-[11px] font-semibold tracking-wider uppercase mb-1 flex items-center gap-1"><Activity size={12}/> Algorithm</p>
                <p className="text-white font-mono text-sm m-0">Isolation Forest</p>
              </div>

              <div>
                <p className="text-[#a8b8d4] text-[11px] font-semibold tracking-wider uppercase mb-1">Threat Threshold</p>
                <p className="text-white font-mono text-sm m-0">{config.anomaly_score_threshold}</p>
              </div>

              <div>
                <p className="text-[#a8b8d4] text-[11px] font-semibold tracking-wider uppercase mb-1">Init Training Size</p>
                <p className="text-white font-mono text-sm m-0">{config.initial_training_size} packets</p>
              </div>

              <div>
                <p className="text-[#a8b8d4] text-[11px] font-semibold tracking-wider uppercase mb-1">UI Buffer Limit</p>
                <p className="text-white font-mono text-sm m-0">{config.max_display_points} max pts</p>
              </div>
            </div>
          </div>
        ) : (
          <p className="text-cyber-text text-sm">Fetching architecture telemetry...</p>
        )}
      </BentoBox>
    </div>
  );
}
