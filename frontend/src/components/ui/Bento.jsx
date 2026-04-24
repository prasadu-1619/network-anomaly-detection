import React from 'react';
import { cn } from '../../utils';
import { motion } from 'framer-motion';
import { Info } from 'lucide-react';

export function BentoBox({ children, className, delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay, ease: "easeOut" }}
      className={cn("cyber-panel p-4 flex flex-col", className)}
    >
      {children}
    </motion.div>
  );
}

export function BentoHeader({ title, icon: Icon, tooltip, colorClasses }) {
  return (
    <div className="flex items-center justify-between mb-4 pb-2 border-b border-white/5 relative group">
      <h3 className={cn("m-0 text-sm font-semibold uppercase tracking-wide flex items-center gap-2", colorClasses)}>
        {Icon && <Icon size={16} />} 
        {title}
      </h3>
      {tooltip && (
        <div className="relative flex items-center justify-center w-5 h-5 rounded hover:bg-cyber-accent/20 border border-white/10 hover:border-cyber-accent text-cyber-text hover:text-cyber-accent cursor-help transition-all">
          <Info size={12} />
          {/* Tooltip text */}
          <div className="absolute bottom-[calc(100%+8px)] right-[-10px] w-60 p-3 bg-[#141423] border border-cyber-accent/30 rounded-lg text-blue-100 text-[11.5px] font-normal leading-relaxed text-left shadow-2xl invisible opacity-0 translate-y-2 group-hover:visible group-hover:opacity-100 group-hover:translate-y-0 transition-all z-50">
            {tooltip}
            <div className="absolute top-full right-3 border-[5px] border-transparent border-t-cyber-accent/30"></div>
          </div>
        </div>
      )}
    </div>
  );
}
