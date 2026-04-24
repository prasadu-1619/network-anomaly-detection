import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, CloudDownload, Sliders } from 'lucide-react';

import { Header } from './components/Header';
import { Dashboard } from './components/Dashboard';
import { Logs } from './components/Logs';
import { Settings } from './components/Settings';

const API_BASE = "http://127.0.0.1:8050";

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [health, setHealth] = useState({ isOffline: true, uptime: 0 });

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch(`${API_BASE}/health`);
        const data = await res.json();
        setHealth({ isOffline: false, uptime: data.uptime_seconds });
      } catch {
        setHealth({ isOffline: true, uptime: 0 });
      }
    };
    
    checkHealth();
    const interval = setInterval(checkHealth, 2000);
    return () => clearInterval(interval);
  }, []);

  const tabs = [
    { id: 'dashboard', label: 'Live Dashboard', icon: <Activity size={16} /> },
    { id: 'logs', label: 'Logs & Export', icon: <CloudDownload size={16} /> },
    { id: 'settings', label: 'Settings', icon: <Sliders size={16} /> },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 pb-12 overflow-x-hidden min-h-screen flex flex-col">
      <Header isOffline={health.isOffline} uptime={health.uptime} />

      {/* Navigation */}
      <div className="flex justify-center mb-8">
        <div className="bg-cyber-panel border border-white/10 rounded-xl p-1.5 shadow-cyber flex items-center justify-center gap-2 w-full max-w-2xl bg-[#121224]/80 backdrop-blur-lg z-10">
          {tabs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`relative flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive ? 'text-cyber-accent' : 'text-[#a8b8d4] hover:text-white hover:bg-white/5'
                } flex-1 outline-none`}
              >
                {isActive && (
                  <motion.div
                    layoutId="active-tab"
                    className="absolute inset-0 bg-cyber-accent/10 border border-cyber-accent/20 rounded-lg"
                    transition={{ type: "spring", stiffness: 300, damping: 30 }}
                  />
                )}
                <span className="relative z-10">{tab.icon}</span>
                <span className="relative z-10">{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Content Area */}
      <div className="flex-1">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.3 }}
          >
            {activeTab === 'dashboard' && <Dashboard />}
            {activeTab === 'logs' && <Logs />}
            {activeTab === 'settings' && <Settings />}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}

export default App;
