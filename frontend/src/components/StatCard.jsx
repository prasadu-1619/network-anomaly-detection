import React from 'react';
import { motion } from 'framer-motion';
import { cn } from '../utils';

export function StatCard({ title, value, icon, valueColorClass, delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.4, delay, ease: "easeOut" }}
      className="stat-card"
    >
      <div className="text-3xl mb-2">{icon}</div>
      <div className="text-[11px] font-semibold text-[#b8b8d4] tracking-widest uppercase mb-1">
        {title}
      </div>
      <div className={cn("text-3xl font-bold m-0 drop-shadow-md", valueColorClass)}>
        {value}
      </div>
    </motion.div>
  );
}
