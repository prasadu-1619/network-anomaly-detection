import React from 'react';
import { Shield, Activity } from 'lucide-react';
import { motion } from 'framer-motion';

export function Header({ uptime, isOffline }) {
  return (
    <motion.div 
      initial={{ y: -50, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.5, ease: "easeOut" }}
      className="text-center py-6 px-5 bg-header-gradient backdrop-blur-xl border-b-2 border-cyber-accent/40 rounded-b-2xl mx-[-1rem] mb-6 shadow-cyber"
    >
      <h1 className="text-white text-4xl font-bold tracking-wide m-0 mb-2 flex items-center justify-center gap-3 drop-shadow-[0_0_20px_rgba(0,212,255,0.6)]">
        <Shield className="text-cyber-accent" size={36} />
        CyberShield <span className="text-cyber-accent">NIDS</span>
      </h1>
      
      {isOffline ? (
        <p className="text-cyber-danger text-sm font-medium tracking-wide m-0">
          ⚠️ Backend offline. Run: python network_anomaly_detector.py
        </p>
      ) : (
        <>
          <p className="text-[#a8b8d4] text-sm font-normal tracking-wide m-0">
            Network Intrusion Detection System — Active Monitoring
          </p>
          <div className="flex items-center justify-center gap-2 mt-2 font-mono text-xs text-[#7bd0ff]">
            <motion.div 
              animate={{ opacity: [1, 0.3, 1] }} 
              transition={{ repeat: Infinity, duration: 2, ease: "easeInOut" }}
            >
              <Activity size={14} className="text-[#00ff88]" />
            </motion.div>
            <span className="tracking-widest">UPTIME: {uptime.toFixed(0)}s</span>
          </div>
        </>
      )}
    </motion.div>
  );
}
